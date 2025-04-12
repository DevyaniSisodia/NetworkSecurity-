import React from 'react';
import Header from './Header';
import Sidebar from './Sidebar';
import Footer from './Footer';
import './Layout.css'; // Assuming you have a CSS file for layout styles
const Layout = ({ children }) => {
  console.log("Layout rendering, children:", children); // Debug log
  return (
    <div className="layout" style={{ border: "3px solid red", padding: "20px" }}>
      <h2>LAYOUT COMPONENT</h2>
      <Header />
      <div className="main-content" style={{ border: "3px solid blue", padding: "20px" }}>
        <Sidebar />
        <div className="content" style={{ border: "3px solid green", padding: "20px" }}>
          <h3>CONTENT AREA</h3>
          {children}
        </div>
        <Footer />
      </div>
    </div>
  );
};

export default Layout;