import React, { useState, useEffect} from "react";
import useSignIn from 'react-auth-kit/hooks/useSignIn';
import { Eye, EyeOff } from "lucide-react";
import { FaUser, FaLock } from "react-icons/fa";
import useIsAuthenticated from 'react-auth-kit/hooks/useIsAuthenticated'
import { useNavigate } from "react-router-dom";
import axios from "axios";

import './Login.css';

const Login = () => {
    const [showPassword, setShowPassword] = useState(false);
    const [usernameOrEmail, setUsernameOrEmail] = useState("");
    const [password, setPassword] = useState("");
    const [remember, setRemember] = useState(false);
    const [dataError, setDataError] = useState("");
    const [loginError, setLoginError] = useState("");

    const signIn = useSignIn();
    const navigate = useNavigate();
    const isAuthenticated = useIsAuthenticated();

    const isDisabled = usernameOrEmail.trim() === "" || password.trim() === "";
    const isDisabled2 = password.trim() === "";

    const spacebar = /\s/;
    const number = /\d/;
    const specialchar = /[!@#$%^&*(),.?":{}|<>]/;

    const ADDRESS = import.meta.env.VITE_ADDRESS;
    const PORT = import.meta.env.VITE_PORT;

    useEffect(() => 
    {
        if (isAuthenticated) 
        {
            navigate('/home');
        }
    }, [isAuthenticated, navigate]);

    const onSubmit = async () => {
        try {
            const response = await axios.post(`${ADDRESS}${PORT}/login`, {
                usernameOrEmail,
                password,
                remember,
            }, {
                withCredentials: true
            });

            if (response.status == 200)
            {
                if(signIn({
                    auth: {
                        token: response.data.access_token,
                        type: 'Bearer'
                    },
                    userState: {
                        name: response.data.username,
                    }
                }))
                {
                    navigate('/home');
                }
            }
        } catch (error) {
            console.error("Błąd podczas logowania: ", error);

            if (error.response && error.response.data && error.response.data.message) {
                setLoginError(error.response.data.message);
            }
            else
            {
                setLoginError("Błąd podczas logowania.");
            }
        }
    };

    const checkUsernameOrEmail = (value) => {
        if (spacebar.test(value)) {
            setDataError("Nazwa użytkownika oraz email nie mogą zawierać spacji.");
            value = value.replace(/\s/g, "");
        }

        setUsernameOrEmail(value);
    };

    const checkPassword = (value) => {
        if (spacebar.test(value)) {
            setDataError("Hasło nie może zawierać spacji.");
            value = value.replace(/\s/g, "");
        } else if (value.length < 8 || value.length > 20) {
            setDataError("Hasło musi zawierać od 8 do 20 znaków.");
        } else if (!number.test(value)) {
            setDataError("Hasło musi zawierać co najmniej jedną cyfrę.");
        } else if (!specialchar.test(value)) {
            setDataError('Hasło musi zawierać co najmniej jeden znak specjalny [!@#$%^&*(),.?":{}|<>].');
        } else {
            setDataError('');
        }

        setPassword(value);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (dataError) return;

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
                            required
                            minLength="5"
                            maxLength="320"
                            placeholder="Nazwa użytkownika lub email"
                            value={usernameOrEmail}
                            onChange={(e) => { checkUsernameOrEmail(e.target.value) }}
                        />
                    </div>
                    <div className="login-group">
                        <FaLock className="login-icons" />
                        <input
                            type={showPassword ? "text" : "password"}
                            id="password"
                            name="password"
                            required
                            minLength="8"
                            maxLength="20"
                            placeholder="Hasło"
                            value={password}
                            onChange={(e) => { checkPassword(e.target.value) }}
                        />
                        <div>
                            <button
                                className="login-button-show-password"
                                type="button"
                                disabled={isDisabled2}
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
                    {loginError &&<div className="login-error-text">
                        <label>{loginError}</label>
                    </div>}
                    <div className="login-controls">
                        <button type="submit" disabled={isDisabled}>
                            Zaloguj się
                        </button>
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