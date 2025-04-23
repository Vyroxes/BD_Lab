import React, { useEffect, useState } from "react";
import { Eye, EyeOff } from "lucide-react";
import { FaUser, FaLock, FaGithub, FaDiscord } from "react-icons/fa";
import { useNavigate } from "react-router-dom";
import { isAuthenticated, authAxios, setTokens } from '../utils/Auth';

import './Login.css';

const Login = ({ onLogin }) => {
    const [showPassword, setShowPassword] = useState(false);
    const [usernameOrEmail, setUsernameOrEmail] = useState("");
    const [password, setPassword] = useState("");
    const [remember, setRemember] = useState(false);
    const [loginError, setLoginError] = useState("");

    const navigate = useNavigate();

    useEffect(() => {
        const checkAuth = async () => {
            const result = await isAuthenticated();
            if (result) {
                navigate("/home");
            }
        };
        checkAuth();
    }, [navigate]);

    const isDisabled = usernameOrEmail.trim() === "" || password.trim() === "";

    const onSubmit = async () => {
        try {
            const response = await authAxios.post("/api/login", {
                usernameOrEmail,
                password,
                remember,
            });

            if (response.status === 200) {
                setTokens(
                    response.data.access_token,
                    response.data.refresh_token,
                    response.data.expire_time,
                    response.data.refresh_expire_time,
                    response.data.username,
                    response.data.email);
                onLogin();
                navigate('/home');
            }
        } catch (error) {
            console.error("Błąd podczas logowania: ", error);

            if (error.response && error.response.data && error.response.data.message) {
                setLoginError(error.response.data.message);
            } else {
                setLoginError("Błąd podczas logowania.");
            }
        }
    };

    const handleGithubLogin = () => {
        window.location.href = "/api/login/github";
    };

    const handleDiscordLogin = () => {
        window.location.href = "/api/login/discord";
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoginError('');
        await onSubmit();
    };

    return (
        <div className="container-login">
            <div className="container-login2">
                <h1>Logowanie</h1>
                <form onSubmit={handleSubmit}>
                    <div className="login-group">
                        <FaUser className="login-icons" />
                        <input
                            type="text"
                            id="usernameOrEmail"
                            name="usernameOrEmail"
                            spellCheck="false"
                            required
                            minLength="5"
                            maxLength="320"
                            placeholder="Nazwa użytkownika lub email"
                            value={usernameOrEmail}
                            onChange={(e) => setUsernameOrEmail(e.target.value)}
                        />
                    </div>
                    <div className="login-group">
                        <FaLock className="login-icons" />
                        <input
                            type={showPassword ? "text" : "password"}
                            id="password"
                            name="password"
                            spellCheck="false"
                            required
                            minLength="8"
                            maxLength="20"
                            placeholder="Hasło"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                        />
                        <div>
                            <button
                                className="login-button-show-password"
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                            >
                                {showPassword ? <Eye size={20} /> : <EyeOff size={20} />}
                            </button>
                        </div>
                    </div>
                    <div className="login-actions">
                        <label>Zapamiętaj mnie</label>
                        <input
                            type="checkbox"
                            id="remember"
                            name="remember"
                            checked={remember}
                            onChange={(e) => setRemember(e.target.checked)}
                        />
                    </div>
                    {loginError && <div className="login-error-text">
                        <label>{loginError}</label>
                    </div>}
                    <div className="login-controls">
                        <button type="submit" disabled={isDisabled}>
                            Zaloguj się
                        </button>
                    </div>
                    <div className="login-socials">
                        <label>Zaloguj się za pomocą</label>
                        <button type="button" onClick={handleGithubLogin}><FaGithub className="social-icon" /></button>
                        <button type="button" onClick={handleDiscordLogin}><FaDiscord  className="social-icon" /></button>
                    </div>
                    <div className="login-register">
                        <label>Nie masz konta?</label>
                        <button type="button" onClick={() => navigate("/register")}>
                            Zarejestruj się
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default Login;