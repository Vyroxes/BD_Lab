import { useState, useEffect } from 'react';
import { MdHighlightOff } from "react-icons/md";
import { AiOutlineProduct } from "react-icons/ai";
import { RxAvatar } from "react-icons/rx";
import { HiCollection } from "react-icons/hi";
import { AiFillStar } from "react-icons/ai";
import { MdOutlineDarkMode } from "react-icons/md";
import { IoIosStats } from "react-icons/io";
import { AiFillMail } from "react-icons/ai";
import { authAxios } from '../utils/Auth';
import { useSearchParams } from 'react-router-dom';

import './Premium.css';

const Premium = () => {
    const [searchParams] = useSearchParams(); 
    const [loading, setLoading] = useState(false);
    const [loading2, setLoading2] = useState(false);
    const [status, setStatus] = useState(false);
    const [subscription, setSubscription] = useState(null);
    const [paymentMsg, setPaymentMsg] = useState(null);
    const [paymentError, setPaymentError] = useState(null);

    const param = searchParams.get('status');

    const apiUrl = import.meta.env.VITE_API_URL;

    useEffect(() => {
        const handleStatus = async () => {
            setPaymentMsg(null);
            setPaymentError(null);

            if (param == 'ok') {
                setStatus(true);
                setPaymentMsg('Płatność zakończona sukcesem.');
                await checkSubscription();
            }
            else if (param == 'cancelled') {
                setStatus(false);
                await checkSubscription();
                await handleCancel(true);
                setPaymentError('Płatność anulowana.');
            }
            else {
                setStatus(false);
                await checkSubscription();
            }

            if (param) {
                const url = new URL(window.location);
                url.searchParams.delete('status');
                window.history.replaceState({}, '', url.pathname + url.search);
            }
        };
        handleStatus();
    }, [searchParams]);

    const checkSubscription = async () => {
        try {
            const response = await authAxios.get(`${apiUrl}/api/payments/status`, {
                withCredentials: true,
            });

            if (response.status === 200 && response.data.has_premium) {
                setSubscription(response.data.subscription);
                setStatus(true);
            }
            else if (response.status === 200 && response.data.subscription && response.data.subscription.status == 'PENDING') {
                setSubscription(response.data.subscription);
                setStatus(false);
                setPaymentError('Trwa przetwarzanie płatności.');
            }
            else {
                setSubscription(null);
                setStatus(false);
            }
        } catch (error) {
            console.error("Wystąpił błąd podczas sprawdzania subskrypcji: ", error);
        }
    };

    const handlePayment = async (plan) => {
        try {
            if (plan === 'PREMIUM') {
                setLoading(true);
            } else {
                setLoading2(true);
            }
            setPaymentError(null);

            const response = await authAxios.post(`${apiUrl}/api/payments/create`, {
                plan,
            }, {
                withCredentials: true,
            });
            
            if (response.status === 200 && response.data.payment_url) {
                window.location.href = response.data.payment_url;
            } else {
                setPaymentError(response.data.error || 'Wystąpił błąd podczas płatności.');
            }
        } catch (error) {
            console.error("Wystąpił błąd podczas płatności: ", error);
            setPaymentError('Wystąpił błąd podczas płatności.');
        } finally {
            setLoading(false);
            setLoading2(false);
        }
    };

    const handleCancel = async (skip) => {
        if (skip == false) {
            const confirmCancel = window.confirm("Czy na pewno chcesz usunąć subskrypcję?");
        
            if (!confirmCancel) {
                return;
            }
        }
        try {
            setPaymentError(null);
            setPaymentMsg(null);
            const response = await authAxios.post(`${apiUrl}/api/payments/set`, {
                status: 'CANCELLED'
            }, {
                withCredentials: true,
            });
            
            if (response.status === 200) {
                if (skip == false) {
                    setPaymentMsg('Subskrypcja została anulowana.');
                }
                setSubscription(null);
                setStatus(false);
            } else {
                setPaymentError('Wystąpił błąd podczas anulowania subskrypcji.');
            }
        } catch (error) {
            console.error("Wystąpił błąd podczas anulowania subskrypcji: ", error);
            setPaymentError('Wystąpił błąd podczas anulowania subskrypcji.');
        }
    };

    return (
        <div className='premium-container'>
            {paymentMsg && <div className="payment-message">{paymentMsg}</div>}
            {paymentError && <div className="error-message">{paymentError}</div>}

            {subscription ? (
                subscription.plan === 'PREMIUM' ? (
                    <div>
                        <h1>Twój aktualny pakiet</h1>
                        <div className='current-subscription'>
                            <h2>{subscription.plan}</h2>
                            <div className='active-subscription'>
                                <p>Twój pakiet jest aktywny do:</p>
                                <p className='subscription-date'>{new Date(subscription.end_date).toLocaleDateString()}</p>
                            </div>
                            <button className='cancel-button' onClick={() => handleCancel(false)}>Anuluj subskrypcję</button>
                        </div>
                        <div className='upgrade-premiumplus'>
                            <h2>Chcesz więcej?</h2>
                            <div className='premiumplus-content'>
                                <h2>PREMIUM+</h2>
                                <h3>14,99 zł</h3>
                                <h4>do końca trwania aktualnego pakietu</h4>
                                <p><AiFillStar className='icons'/>Wszystko co pakiet PREMIUM</p>
                                <p><MdOutlineDarkMode className='icons'/>Motywy kolorystyczne</p>
                                <p><IoIosStats className='icons'/>Zaawansowane statystyki</p>
                                <p><AiFillMail className='icons'/>Powiadomienia o nowych produktach</p>
                                <div className='premiumplus-button'>
                                    <button
                                        type='button'
                                        onClick={() => handlePayment('PREMIUM+_UPGRADE')}
                                        disabled={loading2}
                                    >
                                        {loading2 ? 'Przetwarzanie...' : 'Ulepsz do PREMIUM+'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                ) : (
                    <div>
                        <h1>Twój aktualny pakiet</h1>
                        <div className='current-subscription'>
                            <h2>{subscription.plan}</h2>
                            <div className='active-subscription'>
                                <p>Twój pakiet jest aktywny do:</p>
                                <p className='subscription-date'>{new Date(subscription.end_date).toLocaleDateString()}</p>
                            </div>
                            <button className='cancel-button' onClick={() => handleCancel(false)}>Anuluj subskrypcję</button>
                        </div>
                    </div>
                )
            ) : (
                <div>
                    <h1>Premium</h1>
                    <div className='premium-cards'>
                        <div className='premium-content'>
                            <h2>PREMIUM</h2>
                            <h3>19,99 zł / 30 dni</h3>
                            <p><MdHighlightOff className='icons'/>Brak reklam</p>
                            <p><AiOutlineProduct className='icons'/>Import i eksport produktów</p>
                            <p><RxAvatar className='icons'/>Animowany awatar</p>
                            <p><HiCollection className='icons'/>Większy limit produktów</p>
                            <div className='premium-button'>
                            <button
                                    type='button' 
                                    onClick={() => handlePayment('PREMIUM')}
                                    disabled={loading || status} 
                                >
                                    {loading ? 'Przetwarzanie...' : 'Kup pakiet PREMIUM'}
                                </button>
                            </div>    
                        </div>
                        <div className='premiumplus-content'>
                            <h2>PREMIUM+</h2>
                            <h3>34,99 zł / 30 dni</h3>
                            <p><AiFillStar className='icons'/>Wszystko co pakiet PREMIUM</p>
                            <p><MdOutlineDarkMode className='icons'/>Motywy kolorystyczne</p>
                            <p><IoIosStats className='icons'/>Zaawansowane statystyki</p>
                            <p><AiFillMail className='icons'/>Powiadomienia o nowych produktach</p>
                            <div className='premiumplus-button'>
                                <button 
                                    type='button'
                                    onClick={() => handlePayment('PREMIUM+')}
                                    disabled={loading2 || status}
                                >
                                    {loading2 ? 'Przetwarzanie...' : 'Kup pakiet PREMIUM+'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Premium;