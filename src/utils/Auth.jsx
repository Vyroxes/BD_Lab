import axios from 'axios';
import { jwtDecode } from 'jwt-decode';

const TOKEN_KEY = 'access_token';
const REFRESH_TOKEN_KEY = 'refresh_token';
const USERNAME_KEY = 'username';

const apiUrl = import.meta.env.VITE_API_URL;

export const setTokens = (username, email, accessToken, refreshToken, accessTokenExpire, refreshTokenExpire) => {
    const accessTokenExpireDate = new Date();
    const [days, hours, minutes, seconds] = accessTokenExpire.split(':').map(Number);
    accessTokenExpireDate.setDate(accessTokenExpireDate.getDate() + days);
    accessTokenExpireDate.setHours(accessTokenExpireDate.getHours() + hours);
    accessTokenExpireDate.setMinutes(accessTokenExpireDate.getMinutes() + minutes);
    accessTokenExpireDate.setSeconds(accessTokenExpireDate.getSeconds() + seconds);

    const refreshTokenExpireDate = new Date();
    const [rDays, rHours, rMinutes, rSeconds] = refreshTokenExpire.split(':').map(Number);
    refreshTokenExpireDate.setDate(refreshTokenExpireDate.getDate() + rDays);
    refreshTokenExpireDate.setHours(refreshTokenExpireDate.getHours() + rHours);
    refreshTokenExpireDate.setMinutes(refreshTokenExpireDate.getMinutes() + rMinutes);
    refreshTokenExpireDate.setSeconds(refreshTokenExpireDate.getSeconds() + rSeconds);

    const isSecure = window.location.protocol === 'https:';
    const secureFlag = isSecure ? 'secure;' : '';

    document.cookie = `${TOKEN_KEY}=${accessToken}; path=/; ${secureFlag} SameSite=Lax; expires=${accessTokenExpireDate.toUTCString()};`;
    document.cookie = `${REFRESH_TOKEN_KEY}=${refreshToken}; path=/; ${secureFlag} SameSite=Lax; expires=${refreshTokenExpireDate.toUTCString()};`;
    document.cookie = `${USERNAME_KEY}=${username}; path=/; ${secureFlag} SameSite=Lax; expires=${accessTokenExpireDate.toUTCString()};`;
};

export const getCookie = (name) => {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
};

export const getAccessToken = () => getCookie(TOKEN_KEY);
export const getRefreshToken = () => getCookie(REFRESH_TOKEN_KEY);
export const getUsername = () => getCookie(USERNAME_KEY);

export const clearTokens = () => {
    const cookies = document.cookie.split(";");

    cookies.forEach((cookie) => {
        const cookieName = cookie.split("=")[0].trim();
        document.cookie = `${cookieName}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC;`;
    });
};

export const isAuthenticated = async () => {
    const accessToken = getAccessToken();

    if (!accessToken) {
        const refreshToken = getRefreshToken();
        if (!refreshToken) {
            clearTokens();
            return false;
        }

        try {
            await refreshAccessToken();
            return true;
        } catch (error) {
            console.error('Błąd podczas odświeżania tokenu: ', error);
            clearTokens();
            return false;
        }
    }

    return true;
};

export const refreshAccessToken = async () => {
    try {
        const refreshToken = getRefreshToken();
        if (!refreshToken) {
            console.error('Brak refresh tokenu.');
            return;
        }

        if (isAccessTokenExpiringSoon() || !getAccessToken() || !getUsername()) {
            const response = await axios.post(`${apiUrl}/api/refresh`, {
                refresh_token: refreshToken
            }, {
                withCredentials: true,
            });
            
            if (response.status === 200) {
                setTokens(response.data.username, response.data.email, response.data.access_token, response.data.refresh_token, response.data.expire_time, response.data.refresh_expire_time);
                console.log('Token odświeżony pomyślnie.');
                return response.data.access_token;
            }
        }
    } catch (error) {
        console.error('Błąd poczas odświeżania tokenu: ', error);
        clearTokens();
        throw error;
    }
};

export const getTokenExpireDate = (name) => {
    const token = getCookie(name);
    if (!token) return null;

    try {
        const decodedToken = jwtDecode(token);
        if (decodedToken && decodedToken.exp) {
            return new Date(decodedToken.exp * 1000);
        }
    } catch (error) {
        console.error('Błąd podczas dekodowania tokenu:', error);
        return null;
    }
};

export const isAccessTokenExpiringSoon = () => {
    const expireDate = getTokenExpireDate("access_token");
    if (!expireDate) return false;

    const expireTime = expireDate.getTime();
    const currentTime = new Date().getTime();

    return expireTime - currentTime < 10 * 1000;
};

export const authAxios = axios.create();

authAxios.interceptors.request.use(async (config) => {
    let token = getAccessToken();

    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }

    return config;
}, (error) => Promise.reject(error));

authAxios.interceptors.response.use(
    (response) => response,
    async (error) => {
        const originalRequest = error.config;

        if (error.response?.status === 401 && !originalRequest._retry) {
            originalRequest._retry = true;
            try {
                const newToken = await refreshAccessToken();
                originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
                return authAxios(originalRequest);
            } catch (refreshError) {
                console.error('Błąd poczas odświeżania tokenu: ', refreshError);
                return Promise.reject(refreshError);
            }
        }

        return Promise.reject(error);
    }
);