// const subscriptionProduct = 'pro_01jaqparwy6wqpb0qd5gtcbvkp';
// const extractionsProduct = 'pro_01jawqkzvyk39n2nrprmpdja7c';
const subscriptionItems = {
    'Monthly': { quantity: 1, priceId: 'pri_01jaqpemr2mj9w091g0698fz2g', price: null },
    'Yearly': { quantity: 1, priceId: 'pri_01jawqy5jz6t5yd9vv99fgny8j', price: null }
};
const extractionsItems = {
    '10 extractions': { quantity: 1, priceId: 'pri_01jawqp5xhcj4akwwx1fv90khn', price: null },
    '50 extractions': { quantity: 1, priceId: 'pri_01jawqqq7y1jerrth6m03td1zj', price: null }
};

var user = null;

let transactionInProgress = null;

document.addEventListener('DOMContentLoaded', async function() {

    const token = new URLSearchParams(window.location.search).get('token');

    if (!token) {
        showError();
        return;
    }

    Paddle.Environment.set("sandbox");
    Paddle.Initialize({
        token: 'test_5a3aa38b9488bf3491378548183',
        eventCallback: function(data) {
            console.log('Event callback:', data);
            switch (data.name) {
                case 'checkout.customer.created':
                    sendTransactionInfo(data);
                    break;
                case 'checkout.completed':
                    handleSuccessfulCheckout(data);
                    break;
            }
        }
    });

    await updatePrices();

    verifyToken(token);
});

function verifyToken(token) {
    fetch('/verify_token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token }),
        credentials: 'include'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Token verification failed');
        }
        return response.json();
    })
    .then(data => {
        if (data.user_id) {
            fetchUserInfo(data.user_id);
        } else {
            throw new Error('Invalid user');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showError('Token verification failed. Please try again from the extension.');
    });
}

function updatePrices() {
    return new Promise((resolve, reject) => {
        const request = {
            items: [
                subscriptionItems.Monthly,
                subscriptionItems.Yearly,
                extractionsItems['10 extractions'],
                extractionsItems['50 extractions']
            ]
        };

        Paddle.PricePreview(request).then((result) => {
            result.data.details.lineItems.forEach(item => {
                if (item.price.id === subscriptionItems['Monthly'].priceId) {
                    subscriptionItems['Monthly'].price = item.formattedTotals.total;
                } else if (item.price.id === subscriptionItems['Yearly'].priceId) {
                    subscriptionItems['Yearly'].price = item.formattedTotals.total;
                } else if (item.price.id === extractionsItems['10 extractions'].priceId) {
                    extractionsItems['10 extractions'].price = item.formattedTotals.total;
                } else if (item.price.id === extractionsItems['50 extractions'].priceId) {
                    extractionsItems['50 extractions'].price = item.formattedTotals.total;
                }
            });
            resolve();
        })
        .catch(error => {
            console.error('Error fetching prices:', error);
            reject(error);
        });
    });
}

function showError(message) {
    document.getElementById('content').style.display = 'none';
    const errorDiv = document.getElementById('error-message');
    errorDiv.style.display = 'block';
    errorDiv.innerHTML = `<h2>Access Denied</h2><p>${message}</p>`;
}

function fetchUserInfo(user_id) {
    fetch('/user_info', {
        method: 'GET',
        credentials: 'include'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Not authorized');
        }
        return response.json();
    })
    .then(userData => {
        if (user_id != userData.id) {
            throw new Error('User ID mismatch');
        }
        user = userData;
        document.getElementById('content').style.display = 'block';
        renderUserInfo();
        renderSubscriptionManagement();
        renderCreditManagement();
    })
    .catch(error => {
        console.error('Error fetching user info:', error);
        showError();
    });
}

function renderUserInfo() {
    const userInfoDiv = document.getElementById('user-info');
    userInfoDiv.innerHTML = `
        <p>Email: ${user.email}</p>
        <p>Tier: ${user.tier}</p>
        <p>Extractions left: ${user.extractions_left}</p>
        <p>Paid extractions left: ${user.paid_extractions_left}</p>
        <p>Subscription ends: ${user.subscription_end || 'N/A'}</p>
    `;
}

function renderSubscriptionManagement() {
    const subscriptionDiv = document.getElementById('subscription-management');
    if (user.is_premium) {
        subscriptionDiv.innerHTML = `
            <p>${getMessage('premiumPlanStatus')}</p>
            <button onclick="cancelSubscription()">${getMessage('cancelSubscription')}</button>
        `;
    } else {
        subscriptionDiv.innerHTML = `
            <p>${getMessage('upgradeToPremium')}</p>
            <button onclick="openCheckout([{ priceId: '${subscriptionItems['Monthly'].priceId}', quantity: 1 }])">${getMessage('upgradeMonthly', { price: subscriptionItems['Monthly'].price })}</button>
            <button onclick="openCheckout([{ priceId: '${subscriptionItems['Yearly'].priceId}', quantity: 1 }])">${getMessage('upgradeYearly', { price: subscriptionItems['Yearly'].price })}</button>
        `;
    }
}

function renderCreditManagement() {
    const creditDiv = document.getElementById('credit-management');
    creditDiv.innerHTML = `
        <p>${getMessage('extractionsLeft', { count: user.total_extractions })}</p>
        <div>
            <label for="10-extractions">${getMessage('extractionsLabel', { count: '10', price: extractionsItems['10 extractions'].price })}</label>
            <input type="number" id="10-extractions" min="0" value="0">
        </div>
        <div>
            <label for="50-extractions">${getMessage('extractionsLabel', { count: '50', price: extractionsItems['50 extractions'].price })}</label>
            <input type="number" id="50-extractions" min="0" value="0">
        </div>
        <button id="buy-extractions" onclick="buyExtractions()">${getMessage('buyExtractions')}</button>
    `;
    document.getElementById('buy-extractions').disabled = true;
    // Add event listeners to the input fields
    document.getElementById('10-extractions').addEventListener('input', updateBuyButton);
    document.getElementById('50-extractions').addEventListener('input', updateBuyButton);

    function updateBuyButton() {
        const tenExtractions = parseInt(document.getElementById('10-extractions').value) || 0;
        const fiftyExtractions = parseInt(document.getElementById('50-extractions').value) || 0;
        const buyButton = document.getElementById('buy-extractions');

        // Disable the button if both inputs are 0
        buyButton.disabled = (tenExtractions === 0 && fiftyExtractions === 0);
    }
}

function buyExtractions() {
    const tenExtractions = parseInt(document.getElementById('10-extractions').value);
    const fiftyExtractions = parseInt(document.getElementById('50-extractions').value);
    let items = [];
    if (tenExtractions > 0) {
        items.push({ priceId: extractionsItems['10 extractions'].priceId, quantity: tenExtractions });
    }
    if (fiftyExtractions > 0) {
        items.push({ priceId: extractionsItems['50 extractions'].priceId, quantity: fiftyExtractions });
    }
    if (items.length > 0) {
        openCheckout(items);
    }
}

function openCheckout(items) {
    
    const params = {
        items: items,
        customer: { email: user.email },
        settings: { allowLogout: false },
        customData: { user_id: user.id }
    };
    Paddle.Checkout.open(params);
}

function sendTransactionInfo(eventData) {
    const transactionInfo = {
        paddleCustomerId: eventData.data.customer.id,
        transactionId: eventData.data.transaction_id,
        userId: eventData.data.custom_data.user_id
    };

    fetch('/initiate_transaction', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(transactionInfo),
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        console.log('Transaction info sent to server:', data);
        transactionInProgress = data.transactionId;
    })
    .catch(error => {
        console.error('Error sending transaction info to server:', error);
    });
}

function handleSuccessfulCheckout(eventData) {
    if (!transactionInProgress) {
        console.error('No transaction in progress');
        return;
    }

    const checkoutData = {
        transactionId: transactionInProgress,
        userId: eventData.data.custom_data.user_id
    };

    fetch('/confirm_transaction', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(checkoutData),
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        console.log('Checkout confirmation sent to server:', data);
        transactionInProgress = null;
        fetchUserInfo(checkoutData.userId); // Update user info after successful transaction
    })
    .catch(error => {
        console.error('Error confirming checkout:', error);
    });
}

function sendTransactionDataToServer(eventData) {
    fetch('/update_transaction', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(eventData),
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        console.log('Transaction data sent to server:', data);
    })
    .catch(error => {
        console.error('Error sending transaction data to server:', error);
    });
}

function cancelSubscription() {
    fetch('/cancel_subscription', {
        method: 'POST',
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        console.log('Subscription cancelled:', data);
        fetchUserInfo(user.id);
    })
    .catch(error => {
        console.error('Error cancelling subscription:', error);
    });
}

