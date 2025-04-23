import React, { useState, useEffect } from 'react';
import { MdHighlightOff } from "react-icons/md";
import { AiOutlineProduct } from "react-icons/ai";
import { RxAvatar } from "react-icons/rx";
import { HiCollection } from "react-icons/hi";
import { AiFillStar } from "react-icons/ai";
import { MdOutlineDarkMode } from "react-icons/md";
import { IoIosStats } from "react-icons/io";
import { AiFillMail } from "react-icons/ai";
import { authAxios } from '../utils/Auth';

import './Premium.css';

const Premium = () => {
    const [loading, setLoading] = useState(false);
    const [loading2, setLoading2] = useState(false);
    const [status, setStatus] = useState(false);
    const [subscription, setSubscription] = useState(null);
    const [paymentError, setPaymentError] = useState(null);

    useEffect(() => {
        const checkSubscription = async () => {
            try {
                const response = await authAxios.get('/api/payments/status');

                if (response.status === 200 && response.data.has_premium) {
                    setSubscription(response.data.subscription);
                    setStatus(true);
                }
                else if (response.status === 200 && response.data.subscription) {
                    setStatus(true);
                    setPaymentError('Trwa przetwarzanie płatności.');
                }
            } catch (error) {
                console.error("Wystąpił błąd podczas sprawdzania subskrypcji: ", error);
            }
        };

        checkSubscription();
    }, []);

    const handlePayment = async (plan) => {
        try {
            if (plan === 'PREMIUM') {
                setLoading(true);
            } else {
                setLoading2(true);
            }
            setPaymentError(null);

            const response = await authAxios.post('/api/payments/create', {
                plan
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

    if (subscription) {
        return (
            <div className='premium-container'>
                <h1>Twój aktualny pakiet</h1>
                <div className='current-subscription'>
                    <h2>{subscription.plan}</h2>
                    <p>Twój pakiet jest aktywny do: {new Date(subscription.end_date).toLocaleDateString()}</p>
                </div>
            </div>
        );
    }

    return (
        <div className='premium-container'>
            <h1>Premium</h1>
            {paymentError && <div className="error-message">{paymentError}</div>}
            <div className='premium-cards'>
                <div className='premium-content'>
                    <h2>PREMIUM</h2>
                    <h3>19,99 zł</h3>
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
                    <h3>34,99 zł</h3>
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
    );
};

export default Premium;