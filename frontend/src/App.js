import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Layout from './components/common/Layout';
import Dashboard from './components/Dashboard/Dashboard';
import ThreatMap from './components/ThreatMap/ThreatMap';
import PredictionList from './components/Predictions/PredictionList';
import './App.css';

function App() {
  return (
    <div style={{ padding: "30px" }}>
      <h1>Simple Test App</h1>
      <Dashboard />
    </div>
  );
}
export default App;