import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
import joblib
import logging
import json
from datetime import datetime, timedelta
from database import SessionLocal, RawThreatData, Prediction

logger = logging.getLogger(__name__)

class CyberThreatPredictor:
    def __init__(self, model_path=None):
        self.db = SessionLocal()
        self.model = None
        self.feature_scaler = None
        self.target_encoder = None
        self.lookback_days = 30  # How many days of data to use for prediction
        
        if model_path:
            self.load_model(model_path)
    
    def preprocess_data(self):
        """Extract and preprocess data from the database"""
        # Fetch raw threat data
        raw_data = self.db.query(RawThreatData).all()
        
        if not raw_data:
            logger.warning("No threat data available for training")
            return None, None
        
        # Convert to DataFrame
        data = []
        for item in raw_data:
            try:
                raw_json = json.loads(item.raw_data)
                entry = {
                    'timestamp': item.timestamp,
                    'data_type': item.data_type,
                    'target_sector': item.target_sector or 'Unknown',
                    'target_technology': item.target_technology or 'Unknown',
                    'severity': item.severity or 0.0
                }
                
                # Extract additional features from raw data if available
                if 'attackVector' in raw_json:
                    entry['attack_vector'] = raw_json['attackVector']
                if 'exploitability' in raw_json:
                    entry['exploitability'] = raw_json['exploitability']
                    
                data.append(entry)
            except Exception as e:
                logger.error(f"Error processing threat data {item.id}: {str(e)}")
        
        df = pd.DataFrame(data)
        
        # Convert timestamp to datetime if it's not already
        if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
        # Sort by timestamp
        df = df.sort_values('timestamp')
        
        # Create daily aggregations
        df['date'] = df['timestamp'].dt.date
        daily_data = df.groupby(['date', 'target_sector', 'target_technology']).agg({
            'severity': 'mean',
            'data_type': 'count'  # Count of threats per day/sector/technology
        }).reset_index()
        
        daily_data.rename(columns={'data_type': 'threat_count'}, inplace=True)
        
        # Create time series features
        daily_data['day_of_week'] = pd.to_datetime(daily_data['date']).dt.dayofweek
        daily_data['day_of_month'] = pd.to_datetime(daily_data['date']).dt.day
        daily_data['month'] = pd.to_datetime(daily_data['date']).dt.month
        
        # Create lag features (instead of LSTM sequences)
        for lag in range(1, 8):
            daily_data[f'severity_lag_{lag}'] = daily_data['severity'].shift(lag)
            daily_data[f'threat_count_lag_{lag}'] = daily_data['threat_count'].shift(lag)
        
        # Drop rows with NaN values from the lag features
        daily_data = daily_data.dropna()
        
        # One-hot encode categorical features
        categorical_features = ['target_sector', 'target_technology']
        self.target_encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        encoded_cats = self.target_encoder.fit_transform(daily_data[categorical_features])
        
        # Get the feature names
        encoded_feature_names = self.target_encoder.get_feature_names_out(categorical_features)
        
        # Create a DataFrame with the encoded features
        encoded_df = pd.DataFrame(encoded_cats, columns=encoded_feature_names)
        
        # Concatenate with the original DataFrame
        daily_data = daily_data.reset_index(drop=True)
        daily_data = pd.concat([daily_data, encoded_df], axis=1)
        
        # Prepare target variables
        # Determine severity level: 0 (low), 1 (medium), 2 (high)
        daily_data['severity_level'] = pd.cut(
            daily_data['severity'], 
            bins=[-float('inf'), 4.0, 7.0, float('inf')], 
            labels=[0, 1, 2]
        ).astype(int)
        
        # Get the sector and technology indices
        daily_data['sector_idx'] = daily_data['target_sector'].apply(
            lambda x: list(self.target_encoder.categories_[0]).index(x) if x in self.target_encoder.categories_[0] else 0
        )
        daily_data['tech_idx'] = daily_data['target_technology'].apply(
            lambda x: list(self.target_encoder.categories_[1]).index(x) if x in self.target_encoder.categories_[1] else 0
        )
        
        # Select features for the model
        lag_features = [f'severity_lag_{lag}' for lag in range(1, 8)] + [f'threat_count_lag_{lag}' for lag in range(1, 8)]
        feature_columns = ['day_of_week', 'day_of_month', 'month'] + lag_features + list(encoded_feature_names)
        features = daily_data[feature_columns]
        
        # Targets
        targets = daily_data[['sector_idx', 'tech_idx', 'severity_level']]
        
        # Scale numerical features
        self.feature_scaler = MinMaxScaler()
        scaled_features = self.feature_scaler.fit_transform(features)
        
        return scaled_features, targets
    
    def build_model(self):
        """Build a Random Forest model for threat prediction"""
        # We'll use multiple Random Forest classifiers, one for each prediction target
        sector_model = RandomForestClassifier(n_estimators=100, random_state=42)
        tech_model = RandomForestClassifier(n_estimators=100, random_state=42)
        severity_model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        return {
            'sector': sector_model,
            'tech': tech_model,
            'severity': severity_model
        }
    
    def train(self):
        """Train the prediction models on threat data"""
        X, y = self.preprocess_data()
        
        if X is None or len(X) == 0:
            logger.error("No training data available")
            return False
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Build the models
        self.model = self.build_model()
        
        # Train each model on its respective target
        self.model['sector'].fit(X_train, y_train['sector_idx'])
        self.model['tech'].fit(X_train, y_train['tech_idx'])
        self.model['severity'].fit(X_train, y_train['severity_level'])
        
        # Evaluate the models
        sector_acc = self.model['sector'].score(X_test, y_test['sector_idx'])
        tech_acc = self.model['tech'].score(X_test, y_test['tech_idx'])
        severity_acc = self.model['severity'].score(X_test, y_test['severity_level'])
        
        logger.info(f"Model accuracy - Sector: {sector_acc:.4f}, Tech: {tech_acc:.4f}, Severity: {severity_acc:.4f}")
        
        # Save the model and preprocessing objects
        self.save_model('models/threat_predictor')
        
        return {
            'sector_accuracy': sector_acc,
            'tech_accuracy': tech_acc,
            'severity_accuracy': severity_acc
        }
    
    def predict_threats(self, days_ahead=7):
        """Predict threats for the specified number of days ahead"""
        if not self.model or not self.feature_scaler:
            logger.error("Model not trained or loaded")
            return []
            
        # Get the most recent data for prediction
        recent_data = self._get_recent_data()
        if recent_data.empty:
            logger.warning("No recent data available for prediction")
            return []
            
        # Prepare the data for prediction
        X_pred = self._prepare_prediction_data(recent_data)
        
        if X_pred is None:
            return []
        
        # Make predictions
        predictions = []
        last_data = recent_data.iloc[-1].copy()  # Start with the most recent real data
        
        for i in range(days_ahead):
            # Predict using the trained models
            sector_idx = self.model['sector'].predict([X_pred])[0]
            tech_idx = self.model['tech'].predict([X_pred])[0]
            severity_level = self.model['severity'].predict([X_pred])[0]
            
            # Get prediction confidences
            sector_proba = np.max(self.model['sector'].predict_proba([X_pred])[0])
            tech_proba = np.max(self.model['tech'].predict_proba([X_pred])[0])
            severity_proba = np.max(self.model['severity'].predict_proba([X_pred])[0])
            
            # Average confidence score
            confidence = (sector_proba + tech_proba + severity_proba) / 3 * 100
            
            # Map back to original categories
            sector = self.target_encoder.categories_[0][sector_idx]
            technology = self.target_encoder.categories_[1][tech_idx]
            
            # Map severity level to a score
            if severity_level == 2:
                severity = 8.5  # High
                attack_type = "Critical Vulnerability Exploit"
            elif severity_level == 1:
                severity = 5.5  # Medium
                attack_type = "Common Vulnerability Exploit"
            else:
                severity = 3.0  # Low
                attack_type = "Reconnaissance"
                
            # Calculate prediction date
            prediction_date = datetime.now() + timedelta(days=i+1)
            
            # Store the prediction
            prediction = {
                'date': prediction_date.strftime('%Y-%m-%d'),
                'target_sector': sector,
                'target_technology': technology,
                'attack_type': attack_type,
                'severity': severity,
                'confidence': float(confidence)
            }
            
            predictions.append(prediction)
            
            # Store in database
            db_prediction = Prediction(
                timestamp=prediction_date,
                target_sector=sector,
                target_technology=technology,
                attack_type=attack_type,
                confidence=float(confidence),
                predicted_timeframe=f"{i+1}d",
                features_used=json.dumps(list(recent_data.columns)),
                model_version="RF-v1"
            )
            self.db.add(db_prediction)
            
            # Update features for next prediction (simple simulation)
            # For a true forecast, you would need more sophisticated methods
            X_pred = self._update_prediction_features(X_pred, sector_idx, tech_idx, severity_level)
        
        self.db.commit()
        return predictions
    
    def _update_prediction_features(self, X_pred, sector_idx, tech_idx, severity_level):
        """Update the prediction features for the next step in forecasting"""
        # This is a simplified approach. In a real system, 
        # you'd use a more sophisticated time series forecasting approach.
        
        # Map severity level back to a score
        if severity_level == 2:
            severity = 8.5
        elif severity_level == 1:
            severity = 5.5
        else:
            severity = 3.0
        
        # Shift lag features (like a sliding window)
        new_X = X_pred.copy()
        
        # Update lag features (assuming first 14 features after day/month/week are the lags)
        # This is a simplification - real implementation would be more precise
        for i in range(6):  # Shift the severity lags
            new_X[i] = new_X[i+1]
        new_X[6] = severity / 10.0  # Normalize severity
        
        for i in range(7, 13):  # Shift the threat count lags
            new_X[i] = new_X[i+1]
        new_X[13] = 0.5  # Simplified threat count prediction
        
        return new_X
            
    def _get_recent_data(self):
        """Get the most recent threat data for prediction"""
        # Fetch the most recent data
        cutoff_date = datetime.now() - timedelta(days=self.lookback_days)
        recent_threats = self.db.query(RawThreatData).filter(
            RawThreatData.timestamp >= cutoff_date
        ).all()
        
        if not recent_threats:
            return pd.DataFrame()
            
        # Process similar to the training data
        data = []
        for item in recent_threats:
            try:
                entry = {
                    'timestamp': item.timestamp,
                    'data_type': item.data_type,
                    'target_sector': item.target_sector or 'Unknown',
                    'target_technology': item.target_technology or 'Unknown',
                    'severity': item.severity or 0.0
                }
                data.append(entry)
            except Exception as e:
                logger.error(f"Error processing recent threat data: {str(e)}")
        
        df = pd.DataFrame(data)
        
        # Aggregate to daily data
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        daily_data = df.groupby(['date', 'target_sector', 'target_technology']).agg({
            'severity': 'mean',
            'data_type': 'count'
        }).reset_index()
        
        daily_data.rename(columns={'data_type': 'threat_count'}, inplace=True)
        
        # Add time features
        daily_data['day_of_week'] = pd.to_datetime(daily_data['date']).dt.dayofweek
        daily_data['day_of_month'] = pd.to_datetime(daily_data['date']).dt.day
        daily_data['month'] = pd.to_datetime(daily_data['date']).dt.month
        
        return daily_data
    
    def _prepare_prediction_data(self, recent_data):
        """Prepare recent data for prediction"""
        if len(recent_data) < 8:  # We need at least 7 days for lag features
            logger.warning("Insufficient recent data for prediction (need at least 7 days)")
            return None
            
        # Create lag features
        for lag in range(1, 8):
            recent_data[f'severity_lag_{lag}'] = recent_data['severity'].shift(lag)
            recent_data[f'threat_count_lag_{lag}'] = recent_data['threat_count'].shift(lag)
        
        # Drop rows with NaN values
        recent_data = recent_data.dropna()
        
        if recent_data.empty:
            return None
        
        # One-hot encode categorical features
        categorical_features = ['target_sector', 'target_technology']
        encoded_cats = self.target_encoder.transform(recent_data[categorical_features])
        
        # Get the feature names
        encoded_feature_names = self.target_encoder.get_feature_names_out(categorical_features)
        
        # Create a DataFrame with the encoded features
        encoded_df = pd.DataFrame(encoded_cats, columns=encoded_feature_names)
        
        # Concatenate with the original DataFrame
        recent_data = recent_data.reset_index(drop=True)
        recent_data = pd.concat([recent_data, encoded_df], axis=1)
        
        # Select features for the model (same as in training)
        lag_features = [f'severity_lag_{lag}' for lag in range(1, 8)] + [f'threat_count_lag_{lag}' for lag in range(1, 8)]
        feature_columns = ['day_of_week', 'day_of_month', 'month'] + lag_features + list(encoded_feature_names)
        features = recent_data[feature_columns]
        
        # Scale numerical features
        scaled_features = self.feature_scaler.transform(features)
        
        # Return the most recent data point for prediction
        return scaled_features[-1]
    
    def save_model(self, model_path):
        """Save the model and preprocessing objects"""
        if self.model:
            joblib.dump(self.model, f"{model_path}.pkl")
            joblib.dump(self.feature_scaler, f"{model_path}_scaler.pkl")
            joblib.dump(self.target_encoder, f"{model_path}_encoder.pkl")
            logger.info(f"Model saved to {model_path}")
            return True
        else:
            logger.error("No model to save")
            return False
    
    def load_model(self, model_path):
        """Load the model and preprocessing objects"""
        try:
            self.model = joblib.load(f"{model_path}.pkl")
            self.feature_scaler = joblib.load(f"{model_path}_scaler.pkl")
            self.target_encoder = joblib.load(f"{model_path}_encoder.pkl")
            logger.info(f"Model loaded from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return False