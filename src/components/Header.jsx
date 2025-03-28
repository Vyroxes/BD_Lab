import React, { useState } from "react";
import { CiLogout } from "react-icons/ci";
import useSignOut from 'react-auth-kit/hooks/useSignOut';
import useIsAuthenticated from 'react-auth-kit/hooks/useIsAuthenticated';
import useAuthHeader from 'react-auth-kit/hooks/useAuthHeader';
import useAuthUser from 'react-auth-kit/hooks/useAuthUser';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

import './Header.css';

const Header = () => {
    const isAuthenticated = useIsAuthenticated();
    let authHeader = useAuthHeader();
    const signOut = useSignOut();
    const authUser = useAuthUser();
    const navigate = useNavigate();
    let username = "";

    if(isAuthenticated)
    {
        username = authUser.name;
    }
    
    const handleLogout = async () => {
        try {
            const response = await axios.get(`/api/logout`, {
                headers: {
                    'Authorization': authHeader
                },
                withCredentials: true
            });

            if (response.status == 200)
            {
                signOut();
                navigate('/login');
            }
        } catch (error) {
            console.error("Wystąpił błąd podczas wylogowywania: ", error);
        }
    }

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
                    <li>
                        <a onClick={handleLogout}>{username}&nbsp;<CiLogout className="logout-icon"/></a>
                    </li>
                </ul>
            </nav>
        </header>
    );
};

export default Header;