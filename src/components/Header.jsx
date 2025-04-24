import React, { useEffect, useState } from 'react';
import { CiLogout } from "react-icons/ci";
import { useNavigate, useLocation } from "react-router-dom";
import { getCookie, clearTokens, authAxios } from '../utils/Auth';

import './Header.css';

const Header = () => {
    const [avatarUrl, setAvatarUrl] = useState(null);

    const username = getCookie("username");
    const navigate = useNavigate();
    const location = useLocation();

    const apiUrl = import.meta.env.VITE_API_URL;

    useEffect(() => {
        const fetchAvatar = async () => {
            if (username) {
                try {
                    const response = await authAxios.get(`${apiUrl}/api/user/${username}`);
                    if (response.status === 200) {
                        setAvatarUrl(response.data.avatar_url);
                    }
                } catch (error) {
                    console.error("Błąd podczas pobierania avatara: ", error);
                }
            }
        };

        fetchAvatar();
    }, [username]);

    const handleLogout = async () => {
        try {
            const refreshToken = getCookie('refresh_token');

            if (!refreshToken) {
                console.error("Brak refresh tokenu");
                clearTokens();
                navigate("/login");
                return;
            }

            await authAxios.post(`${apiUrl}/api/logout`, {
                refresh_token: getCookie("refresh_token")
            });
            
            console.log("Wylogowano pomyślnie");
            // await authAxios.get(`${apiUrl}/api/clear-session`);
            clearTokens();
            navigate('/login');
        } catch (error) {
            console.error("Błąd podczas wylogowania: ", error);
            clearTokens();
            navigate('/login');
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
                    <li className={location.pathname === "/premium" ? "active" : ""}>
                        <a href="/premium">PREMIUM</a>
                    </li>
                    <li className={location.pathname === `/user` ? "active" : ""}>
                        <a href={`/users/${username}`}>
                            <img
                                src={avatarUrl || "/unknown_avatar.jpg"}
                                alt={username}
                                className="avatar"
                                onError={(e) => {
                                    e.target.onerror = null;
                                    e.target.src = "/unknown_avatar.jpg";
                                }}
                                loading="lazy"
                            />
                            {username}
                        </a>
                    </li>
                    <li onClick={(e) => {
                        e.preventDefault();
                        handleLogout();
                    }}>
                        <a><CiLogout className="logout-icon"/></a>
                    </li>
                </ul>
            </nav>
        </header>
    );
};

export default Header;