import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { authAxios, clearTokens, getCookie, getTokenExpireDate } from '../utils/Auth';

import './User.css';

const User = () => {
    const [accessTokenExpiration, setAccessTokenExpiration] = useState(null);
    const [timeToAccessTokenExpire, setTimeToAccessTokenExpire] = useState(null);
    const [refreshTokenExpiration, setRefreshTokenExpiration] = useState(null);
    const [timeToRefreshTokenExpire, setTimeToRefreshTokenExpire] = useState(null);
    const [loading, setLoading] = useState(true);
    const [email, setEmail] = useState(null); 
    const [avatarUrl, setAvatarUrl] = useState(null);

    const { username } = useParams();

    const navigate = useNavigate();
    const currentUsername = getCookie('username');

    const adminUsername = import.meta.env.VITE_ADMIN_USERNAME;
    const apiUrl = import.meta.env.VITE_API_URL;

    useEffect(() => {
        const interval = setInterval(() => {
            const expireDate = getTokenExpireDate("access_token");
            if (expireDate) {
                const currentTime = new Date().getTime();
                const timeLeft = expireDate.getTime() - currentTime;
    
                if (timeLeft > 0) {
                    const days = Math.floor(timeLeft / (1000 * 60 * 60 * 24));
                    const hours = Math.floor((timeLeft % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                    const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
                    const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);
                    setTimeToAccessTokenExpire(`${days}d ${hours}h ${minutes}m ${seconds}s`);
                } else {
                    setTimeToAccessTokenExpire("Access token wygasł.");
                    clearInterval(interval);
                }
            } else {
                setTimeToAccessTokenExpire("Brak danych.");
                clearInterval(interval);
            }
        }, 1000);
    
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        const interval = setInterval(() => {
            const expireDate = getTokenExpireDate("refresh_token");
            if (expireDate) {
                const currentTime = new Date().getTime();
                const timeLeft = expireDate.getTime() - currentTime;
    
                if (timeLeft > 0) {
                    const days = Math.floor(timeLeft / (1000 * 60 * 60 * 24));
                    const hours = Math.floor((timeLeft % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                    const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
                    const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);
                    setTimeToRefreshTokenExpire(`${days}d ${hours}h ${minutes}m ${seconds}s`);
                } else {
                    setTimeToRefreshTokenExpire("Refresh token wygasł.");
                    clearInterval(interval);
                }
            } else {
                setTimeToRefreshTokenExpire("Brak danych.");
                clearInterval(interval);
            }
        }, 1000);
    
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        if (username) {
            fetchUserData();
            setAccessTokenExpiration(
                getTokenExpireDate("access_token") 
                    ? getTokenExpireDate("access_token").toLocaleString() 
                    : "Brak danych"
            );
            setRefreshTokenExpiration(
                getTokenExpireDate("refresh_token") 
                    ? getTokenExpireDate("refresh_token").toLocaleString() 
                    : "Brak danych"
            );
        }
    }, [username]);

    const fetchUserData = async () => {
        try {
            const response = await authAxios.get(`${apiUrl}/api/user/${username}`);
            if (response.status === 200) {
                setEmail(response.data.email);
                setAvatarUrl(response.data.avatar_url);
                setLoading(false);
            } else {
                navigate('/home');
            }
        } catch (error) {
            console.error("Błąd podczas pobierania danych użytkownika: ", error);
            navigate('/home');
        }
    };

    const deleteAccount = async () => {
        const confirmDelete = window.confirm("Czy na pewno chcesz usunąć konto?");
        
        if (!confirmDelete) {
            return;
        }
        try {
            const response = await authAxios.delete(`${apiUrl}/api/delete-account/${username}`);
            if (response.status === 200) {
                console.log("Usunięto konto pomyślnie");
                clearTokens();
                navigate('/login');
            }
        }
        catch (error) {
            console.error("Błąd podczas usuwania konta: ", error);
        }
    };

    if(loading) {
        return;
    }

    return (
        <div className="user-container">
            <h1>Profil użytkownika</h1>
            <div className="user-header">
                    <img
                    src={avatarUrl || "/unknown_avatar.jpg"}
                    alt={username}
                    className="user-avatar"
                    onError={(e) => {
                        e.target.onerror = null;
                        e.target.src = "/unknown_avatar.jpg";
                    }}
                    loading="lazy"
                    />
                <h1>{username}</h1>
                <a>{email}</a>
            </div>
            <div className="user-stats">
                {username === currentUsername && currentUsername === adminUsername && (<>
                    <h2>Informacje administratora</h2>
                    <li>Access token:</li>
                    <textarea readOnly value={getCookie("access_token") || "brak"}></textarea>
                    <li>Wygaśnięcie access tokenu:
                        <a>{accessTokenExpiration || "brak"}</a>
                    </li>
                    <li>Czas do wygaśnięcia access tokenu:
                        <a>{timeToAccessTokenExpire || "brak"}</a>
                    </li>
                    <li>Refresh token:</li>
                    <textarea readOnly value={getCookie("refresh_token") || "brak"}></textarea>
                    <li>Wygaśnięcie refresh tokenu:
                        <a>{refreshTokenExpiration || "brak"}</a>
                    </li>
                    <li>Czas do wygaśnięcia refresh tokenu:
                        <a>{timeToRefreshTokenExpire}</a>
                    </li>
                    <li>Session token:</li>
                    <textarea readOnly value={getCookie("session") || "brak"}></textarea>
                </>)}
            </div>
            <div className="user-actions">
                {(username === currentUsername || currentUsername === adminUsername) && (<button className='delete-account-button' onClick={() => deleteAccount()}>Usuń konto</button>)}
            </div>
        </div>
    );
};

export default User;