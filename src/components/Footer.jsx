import React from "react";

import './Footer.css';

const Footer = () => {
  return (
    <footer className="footer">
      <p>
        {new Date().getFullYear()}. Strona stworzona przez Michała Ruska, Łukasza Iwańskiego
      </p>
    </footer>
  );
};

export default Footer;