import React, { useState } from "react";
import { CiLogout } from "react-icons/ci";
import useSignOut from 'react-auth-kit/hooks/useSignOut';
import useIsAuthenticated from 'react-auth-kit/hooks/useIsAuthenticated'
import useAuthUser from 'react-auth-kit/hooks/useAuthUser'

import './Header.css';

const Header = () => {
    const isAuthenticated = useIsAuthenticated();
    const signOut = useSignOut();
    const authUser = useAuthUser();
    let username = "";

    if(isAuthenticated)
    {
        username = authUser.name;
    }
    
    const handleLogout = () => {
        signOut();
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
                    <li onClick={handleLogout}>
                        <a href="/login">{username}&nbsp;<CiLogout className="logout-icon"/></a>
                    </li>
                </ul>
            </nav>
        </header>
    );
};

export default Header;