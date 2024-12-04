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

// Add loading state variables
let isVerifyingToken = false;
let isFetchingUserInfo = false;
let isCancellingSubscription = false;
let isUpdatingPrices = false;

document.addEventListener('DOMContentLoaded', async function() {
    try {
        await CSRFProtection.initialize();

        const token = new URLSearchParams(window.location.search).get('token');

        if (!token) {
            showError('noTokenProvided');
            return;
        }

        Paddle.Environment.set("sandbox");
        Paddle.Initialize({
            token: 'test_5a3aa38b9488bf3491378548183',
            eventCallback: function(data) {
                console.log('Event callback:', data);
                switch (data.name) {
                    case 'checkout.loaded':
                        sendTransactionInfo(data);
                        break;
                    case 'checkout.completed':
                        handleSuccessfulCheckout(data);
                        break;
                    case 'checkout.closed':
                        transactionInProgress = null;
                        removeLoadingStates();
                        break;
                }
            }
        });

        await updatePrices();
        await verifyToken(token);
    } catch (error) {
        console.error('Initialization error:', error);
        showError('initializationError');
    } finally {
        document.getElementById('loading-overlay').style.display = 'none';
    }
});

async function verifyToken(token) {
    if (isVerifyingToken) return;
    isVerifyingToken = true;
    
    try {
        const response = await fetchWithRateLimit(fetchWithCSRF, '/verify-token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: token }),
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error('Token verification failed');
        }
        
        const data = await response.json();
        if (data.user_id) {
            await fetchUserInfo(data.user_id);
        } else {
            throw new Error('Invalid user');
        }
    } catch (error) {
        console.error('Error:', error);
        showError('tokenVerificationFailed');
    } finally {
        isVerifyingToken = false;
    }
}

async function updatePrices() {
    if (isUpdatingPrices) return;
    isUpdatingPrices = true;
    
    try {
        const request = {
            items: [
                subscriptionItems.Monthly,
                subscriptionItems.Yearly,
                extractionsItems['10 extractions'],
                extractionsItems['50 extractions']
            ]
        };

        const result = await Paddle.PricePreview(request);
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
    } catch (error) {
        console.error('Error fetching prices:', error);
        showError('errorFetchingPrices');
    } finally {
        isUpdatingPrices = false;
    }
}

async function fetchUserInfo(user_id) {
    if (isFetchingUserInfo) return;
    isFetchingUserInfo = true;
    
    const contentDiv = document.getElementById('content');
    contentDiv.classList.add('loading');
    
    try {
        const response = await fetchWithRateLimit(fetch, '/user-info', {
            method: 'GET',
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error('Not authorized');
        }
        
        const userData = await response.json();
        if (user_id != userData.id) {
            throw new Error('User ID mismatch');
        }
        
        user = userData;
        contentDiv.style.display = 'block';
        renderUserInfo();
        renderSubscriptionManagement();
        renderCreditManagement();
    } catch (error) {
        console.error('Error fetching user info:', error);
        showError('errorFetchingUserInfo');
    } finally {
        isFetchingUserInfo = false;
        contentDiv.classList.remove('loading');
    }
}

async function cancelSubscription() {
    if (isCancellingSubscription) return;
    
    const confirmCancel = confirm(getMessage('confirmCancelSubscription'));
    if (!confirmCancel) return;
    
    isCancellingSubscription = true;
    const subscriptionDiv = document.getElementById('subscription-management');
    subscriptionDiv.classList.add('loading');
    
    try {
        const response = await fetchWithRateLimit(fetchWithCSRF, '/cancel-subscription', {
            method: 'POST',
            credentials: 'include'
        });
        
        const data = await response.json();
        console.log('Subscription cancelled:', data);
        await fetchUserInfo(user.id);
    } catch (error) {
        console.error('Error cancelling subscription:', error);
        alert(getMessage('errorCancellingSubscription'));
    } finally {
        isCancellingSubscription = false;
        subscriptionDiv.classList.remove('loading');
    }
}

function addLoadingStates() {
    const buyButton = document.getElementById('buy-extractions');
    const cancelButton = document.getElementById('cancel-subscription');
    const monthlyUpgrade = document.getElementById('monthly-upgrade');
    const yearlyUpgrade = document.getElementById('yearly-upgrade');

    for (const button of [buyButton, cancelButton, monthlyUpgrade, yearlyUpgrade]) {
        if (button) {
            button.classList.add('loading');
            button.disabled = true;
        }
    }
}

function removeLoadingStates() {
    const buyButton = document.getElementById('buy-extractions');
    const cancelButton = document.getElementById('cancel-subscription');
    const monthlyUpgrade = document.getElementById('monthly-upgrade');
    const yearlyUpgrade = document.getElementById('yearly-upgrade');

    for (const button of [buyButton, cancelButton, monthlyUpgrade, yearlyUpgrade]) {
        if (button) {
            button.classList.remove('loading');
            button.disabled = false;
        }
    }
    updateBuyButton();
}

function openCheckout(items) {
    if (transactionInProgress) return;
    
    addLoadingStates();
    
    const params = {
        items: items,
        customer: { email: user.email },
        settings: { allowLogout: false },
        customData: { user_id: user.id }
    };
    
    Paddle.Checkout.open(params);
}

function showError(message) {
    document.getElementById('content').style.display = 'none';
    const errorDiv = document.getElementById('error-message');
    errorDiv.style.display = 'block';
    errorDiv.innerHTML = `<h2>Access Denied</h2><p>${getMessage(message)}</p>`;
}

function renderUserInfo() {
    const userInfoDiv = document.getElementById('user-info');
    userInfoDiv.innerHTML = `
        <p>${getMessage('email')}: ${user.email}</p>
        <p>${getMessage('tier')}: ${user.tier}</p>
        <p>${getMessage('extractionsLeft')}: ${user.extractions_left}</p>
        <p>${getMessage('paidExtractionsLeft')}: ${user.paid_extractions_left}</p>
    `;
}

const debouncedOpenCheckout = debounce(openCheckout);
const debouncedCancelSubscription = debounce(cancelSubscription);

function renderSubscriptionManagement() {
    const subscriptionDiv = document.getElementById('subscription-management');
    if (user.is_premium) {
        subscriptionDiv.innerHTML = `
            <p>${getMessage('premiumPlanStatus')}</p>
            ${user.subscription_next_billing ? `
                <p>${getMessage('nextBilling')}: ${user.subscription_next_billing}</p>
                <button id="cancel-subscription" onclick="debouncedCancelSubscription()">${getMessage('cancelSubscription')}</button>
            ` : `<p>${getMessage('subscriptionEnd')}: ${user.subscription_end || 'N/A'}</p>`}
        `;
    } else {
        subscriptionDiv.innerHTML = `
            <p>${getMessage('upgradeToPremium')}</p>
            <button id="monthly-upgrade" onclick="debouncedOpenCheckout([{ priceId: '${subscriptionItems['Monthly'].priceId}', quantity: 1 }])">${getMessage('upgradeMonthly', { price: subscriptionItems['Monthly'].price })}</button>
            <button id="yearly-upgrade" onclick="debouncedOpenCheckout([{ priceId: '${subscriptionItems['Yearly'].priceId}', quantity: 1 }])">${getMessage('upgradeYearly', { price: subscriptionItems['Yearly'].price })}</button>
        `;
    }
}

function updateBuyButton() {
    const tenExtractions = parseInt(document.getElementById('10-extractions').value) || 0;
    const fiftyExtractions = parseInt(document.getElementById('50-extractions').value) || 0;
    const buyButton = document.getElementById('buy-extractions');

    // Disable the button if both inputs are 0
    buyButton.disabled = (tenExtractions === 0 && fiftyExtractions === 0);
}

const debouncedUpdateBuyButton = debounce(updateBuyButton);

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

const debouncedBuyExtractions = debounce(buyExtractions);

function renderCreditManagement() {
    const creditDiv = document.getElementById('credit-management');
    creditDiv.innerHTML = `
        <p>${getMessage('totalExtractionsLeft', { count: user.total_extractions })}</p>
        <div>
            <label for="10-extractions">${getMessage('extractionsLabel', { count: '10', price: extractionsItems['10 extractions'].price })}</label>
            <input type="number" id="10-extractions" min="0" value="0">
        </div>
        <div>
            <label for="50-extractions">${getMessage('extractionsLabel', { count: '50', price: extractionsItems['50 extractions'].price })}</label>
            <input type="number" id="50-extractions" min="0" value="0">
        </div>
        <button id="buy-extractions" onclick="debouncedBuyExtractions()">${getMessage('buyExtractions')}</button>
    `;
    document.getElementById('buy-extractions').disabled = true;
    // Add event listeners to the input fields
    document.getElementById('10-extractions').addEventListener('input', debouncedUpdateBuyButton);
    document.getElementById('50-extractions').addEventListener('input', debouncedUpdateBuyButton);
}

function sendTransactionInfo(eventData) {
    const transactionInfo = {
        paddleCustomerId: eventData.data.customer.id,
        transactionId: eventData.data.transaction_id,
        userId: eventData.data.custom_data.user_id
    };

    fetchWithRateLimit(fetchWithCSRF, '/initiate-transaction', {
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

    fetchWithRateLimit(fetchWithCSRF, '/confirm-transaction', {
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
    fetchWithRateLimit(fetchWithCSRF, '/update-transaction', {
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