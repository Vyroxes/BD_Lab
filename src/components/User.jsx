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
    const [github_id, setGithubId] = useState(null);
    const [discord_id, setDiscordId] = useState(null);
    const [accountCreated, setAccountCreated] = useState(null);

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
                    ? getTokenExpireDate("access_token").toLocaleString('pl-PL', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                    }) 
                    : "Brak danych"
            );
            setRefreshTokenExpiration(
                getTokenExpireDate("refresh_token") 
                    ? getTokenExpireDate("refresh_token").toLocaleString('pl-PL', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                    })  
                    : "Brak danych"
            );
        }
    }, [username]);

    const fetchUserData = async () => {
        try {
            const response = await authAxios.get(`${apiUrl}/api/user/${username}`, {
                withCredentials: true,
            });

            if (response.status === 200) {
                setEmail(response.data.email);
                setAvatarUrl(response.data.avatar_url);
                setGithubId(response.data.github_id);
                setDiscordId(response.data.discord_id);
                const date = new Date(response.data.account_created);
                const formattedDate = date.toLocaleString('pl-PL', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                });
                setAccountCreated(formattedDate);
                setLoading(false);
                console.log(response.data);
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
            const response = await authAxios.delete(`${apiUrl}/api/delete-account/${username}`, {
                withCredentials: true,
            });

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
                <p>{email}</p>
            </div>
            {(username === currentUsername || currentUsername === adminUsername) && (<div className="user-stats">
                <h2>Informacje użytkownika</h2>
                <li>Połączony z Github:
                    <p>{github_id ? `Tak (${github_id})` : "nie"}</p>
                </li>
                <li>Połączony z Discord:
                    <p>{discord_id ? `Tak (${discord_id})` : "nie"}</p>
                </li>
                <li>Data utworzenia konta:
                    <p>{accountCreated}</p>
                </li>
                {currentUsername === adminUsername && (<>
                    <h2>Informacje administratora</h2>
                    <li>Access token:</li>
                    <textarea readOnly value={getCookie("access_token") || "brak"}></textarea>
                    <li>Wygaśnięcie access tokenu:
                        <p>{accessTokenExpiration || "brak"}</p>
                    </li>
                    <li>Czas do wygaśnięcia access tokenu:
                        <p>{timeToAccessTokenExpire || "brak"}</p>
                    </li>
                    <li>Refresh token:</li>
                    <textarea readOnly value={getCookie("refresh_token") || "brak"}></textarea>
                    <li>Wygaśnięcie refresh tokenu:
                        <p>{refreshTokenExpiration || "brak"}</p>
                    </li>
                    <li>Czas do wygaśnięcia refresh tokenu:
                        <p>{timeToRefreshTokenExpire}</p>
                    </li>
                    <li>Session token:</li>
                    <textarea readOnly value={getCookie("session") || "brak"}></textarea>
                </>)}
            </div>
            )}
            <div className="user-actions">
                {(username === currentUsername || currentUsername === adminUsername) && (<button className='delete-account-button' onClick={() => deleteAccount()}>Usuń konto</button>)}
            </div>
        </div>
    );
};

export default User;