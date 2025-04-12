import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
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
        self.sequence_length = 7  # Sequence length for LSTM
        
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
        
        # One-hot encode categorical features
        categorical_features = ['target_sector', 'target_technology']
        self.target_encoder = OneHotEncoder(sparse=False, handle_unknown='ignore')
        encoded_cats = self.target_encoder.fit_transform(daily_data[categorical_features])
        
        # Get the feature names
        encoded_feature_names = self.target_encoder.get_feature_names_out(categorical_features)
        
        # Create a DataFrame with the encoded features
        encoded_df = pd.DataFrame(encoded_cats, columns=encoded_feature_names)
        
        # Concatenate with the original DataFrame
        daily_data = daily_data.reset_index(drop=True)
        daily_data = pd.concat([daily_data, encoded_df], axis=1)
        
        # Select features for the model
        feature_columns = ['severity', 'threat_count', 'day_of_week', 'day_of_month', 'month'] + list(encoded_feature_names)
        features = daily_data[feature_columns]
        
        # Scale numerical features
        self.feature_scaler = MinMaxScaler()
        scaled_features = self.feature_scaler.fit_transform(features)
        
        # Create sequences for LSTM
        X, y = self._create_sequences(scaled_features, daily_data)
        
        return X, y
    
    def _create_sequences(self, scaled_data, daily_data):
        """Create sequences for LSTM training"""
        X, y = [], []
        
        for i in range(len(scaled_data) - self.sequence_length):
            # Input sequence
            seq = scaled_data[i:i + self.sequence_length]
            X.append(seq)
            
            # Target: predicting if there will be a high-severity threat in the next day
            # We'll consider severity > 7.0 as high
            next_day = i + self.sequence_length
            target_sector = daily_data.iloc[next_day]['target_sector']
            target_tech = daily_data.iloc[next_day]['target_technology']
            severity = daily_data.iloc[next_day]['severity']
            
            # Create a target vector [sector_index, technology_index, severity_level]
            # We'll simplify this for the demo, but you could use more complex targets
            sector_idx = list(self.target_encoder.categories_[0]).index(target_sector) if target_sector in self.target_encoder.categories_[0] else 0
            tech_idx = list(self.target_encoder.categories_[1]).index(target_tech) if target_tech in self.target_encoder.categories_[1] else 0
            
            # Severity level: 0 (low), 1 (medium), 2 (high)
            if severity > 7.0:
                sev_level = 2  # High
            elif severity > 4.0:
                sev_level = 1  # Medium
            else:
                sev_level = 0  # Low
                
            y.append([sector_idx, tech_idx, sev_level])
        
        return np.array(X), np.array(y)
    
    def build_model(self, input_shape, output_shape):
        """Build the LSTM model architecture"""
        model = Sequential([
            LSTM(64, return_sequences=True, input_shape=input_shape),
            Dropout(0.2),
            LSTM(32),
            Dropout(0.2),
            Dense(32, activation='relu'),
            Dense(output_shape, activation='softmax')
        ])
        
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def train(self, epochs=50, batch_size=32):
        """Train the LSTM model on threat data"""
        X, y = self.preprocess_data()
        
        if X is None or len(X) == 0:
            logger.error("No training data available")
            return False
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Build the model
        input_shape = (X_train.shape[1], X_train.shape[2])
        output_shape = y_train.shape[1]
        self.model = self.build_model(input_shape, output_shape)
        
        # Set up callbacks
        callbacks = [
            EarlyStopping(patience=5, restore_best_weights=True),
            ModelCheckpoint('models/best_threat_model.h5', save_best_only=True)
        ]
        
        # Train the model
        history = self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_data=(X_test, y_test),
            callbacks=callbacks
        )
        
        # Save the model and preprocessing objects
        self.save_model('models/threat_predictor')
        
        # Return training history
        return history.history
    
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
        
        # Make predictions
        predictions = []
        for i in range(days_ahead):
            # Predict the next day
            pred = self.model.predict(X_pred[-1:])
            
            # Decode the prediction
            sector_idx = np.argmax(pred[0, :len(self.target_encoder.categories_[0])])
            tech_start = len(self.target_encoder.categories_[0])
            tech_end = tech_start + len(self.target_encoder.categories_[1])
            tech_idx = np.argmax(pred[0, tech_start:tech_end])
            severity_level = np.argmax(pred[0, tech_end:])
            
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
                'confidence': float(np.max(pred[0])) * 100  # Convert to percentage
            }
            
            predictions.append(prediction)
            
            # Store in database
            db_prediction = Prediction(
                timestamp=prediction_date,
                target_sector=sector,
                target_technology=technology,
                attack_type=attack_type,
                confidence=float(np.max(pred[0])) * 100,
                predicted_timeframe=f"{i+1}d",
                features_used=json.dumps(list(recent_data.columns)),
                model_version="LSTM-v1"
            )
            self.db.add(db_prediction)
        
        self.db.commit()
        return predictions
            
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
        
        # Select features for the model
        feature_columns = ['severity', 'threat_count', 'day_of_week', 'day_of_month', 'month'] + list(encoded_feature_names)
        features = recent_data[feature_columns]
        
        # Scale numerical features
        scaled_features = self.feature_scaler.transform(features)
        
        # Create sequences for LSTM
        sequences = []
        for i in range(len(scaled_features) - self.sequence_length + 1):
            seq = scaled_features[i:i + self.sequence_length]
            sequences.append(seq)
        
        return np.array(sequences)
    
    def save_model(self, model_path):
        """Save the model and preprocessing objects"""
        if self.model:
            self.model.save(f"{model_path}.h5")
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
            self.model = load_model(f"{model_path}.h5")
            self.feature_scaler = joblib.load(f"{model_path}_scaler.pkl")
            self.target_encoder = joblib.load(f"{model_path}_encoder.pkl")
            logger.info(f"Model loaded from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return False