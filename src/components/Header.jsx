
import React from 'react';
import { CiLogout } from "react-icons/ci";
import { useNavigate } from 'react-router-dom';
import { isAuthenticated, getCookie, clearTokens, authAxios } from '../utils/Auth';

import './Header.css';

const Header = () => {
    const username = isAuthenticated() ? getCookie("username") : "";
    const navigate = useNavigate();

    const handleLogout = async () => {
        try {
            const response = await authAxios.post("/api/logout", {
                refresh_token: getCookie("refresh_token")
            });
            
            await authAxios.get("/api/clear-session");

            if (response.status === 200) {
                console.log("Wylogowano pomyślnie");
                clearTokens();
                navigate('/login');
            }
        } catch (error) {
            console.error("Błąd podczas wylogowania: ", error);
        }
    };

    return (
        <header className="header">
            <nav className="nav">
                <ul>
                    <li className={location.pathname === "/home" ? "active" : ""}>
                        <a href="/home">STRONA GŁÓWNA</a>
                    </li>
                    <li className={location.pathname === "/products" ? "active" : ""}>
                        <a href="/products">PRODUKTY</a>
                    </li>
                    {isAuthenticated() && (
                        <li onClick={(e) => {
                            e.preventDefault();
                            handleLogout();
                        }}>
                            <a>{username}&nbsp;<CiLogout className="logout-icon"/></a>
                        </li>
                    )}
                </ul>
            </nav>
        </header>
    );
};

export default Header;