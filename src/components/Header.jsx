import { useEffect, useState } from 'react';
import { CiLogout } from "react-icons/ci";
import { useNavigate, useLocation } from "react-router-dom";
import { getCookie, clearTokens, authAxios, refreshAccessToken } from '../utils/Auth';

import './Header.css';

const Header = () => {
    const [avatarUrl, setAvatarUrl] = useState(null);

    const [username, setUsername] = useState(getCookie("username"));
    const navigate = useNavigate();
    const location = useLocation();

    const apiUrl = import.meta.env.VITE_API_URL;

    useEffect(() => {
        const interval = setInterval(() => {
            const accessToken = getCookie("access_token");
            const refreshToken = getCookie("refresh_token");
            const currentUsername = getCookie("username");

            if (currentUsername !== username) {
                setUsername(currentUsername);
            }
            if (currentUsername == undefined || currentUsername == null || currentUsername == "" || accessToken == undefined || accessToken == null || accessToken == "") {
                refreshAccessToken();
            }
            if ((accessToken == undefined || accessToken == null || accessToken == "") && (refreshToken == undefined || refreshToken == null || refreshToken == "")) {
                clearTokens();
                navigate("/login");
            }
        }, 1000);
        return () => clearInterval(interval);
    }, [username]);

    useEffect(() => {
        const fetchAvatar = async () => {
            if (username) {
                try {
                    const response = await authAxios.get(`${apiUrl}/api/user/${username}`, {
                        withCredentials: true,
                    });
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
            }, {
                withCredentials: true,
            });
            
            clearTokens();
            navigate('/login');
            console.log("Wylogowano pomyślnie");
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
                        <p onClick={() => navigate("/home")}>
                            STRONA GŁÓWNA
                        </p>
                    </li>
                    <li className={location.pathname.startsWith("/product") ? "active" : ""}>
                        <p onClick={() => navigate("/products")}>
                            PRODUKTY
                        </p>
                    </li>
                    <li className={location.pathname.startsWith("/premium") ? "active" : ""}>
                        <p onClick={() => navigate("/premium")}>
                            PREMIUM
                        </p>
                    </li>
                    <li className={location.pathname.startsWith(`/user`) ? "active" : ""}>
                        <p onClick={() => navigate(`/users/${username}`)}>
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
                        </p>
                    </li>
                    <li className="logout-nav" onClick={(e) => {
                        e.preventDefault();
                        handleLogout();
                    }}>
                        <p><CiLogout className="logout-icon"/></p>
                    </li>
                </ul>
            </nav>
        </header>
    );
};

export default Header;