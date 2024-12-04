let currentLanguage = 'en';

function loadLocalization(language) {
    return fetch(`https://cvify.xyz/static/_locales/${language}/payments.json`)
        .then(response => response.json())
        .catch(error => {
            console.error('Error loading localization:', error);
            return {};
        });
}

function getMessage(key, substitutions = {}) {
    const message = window.localization[key];
    if (!message) return key;

    let localizedMessage = message.message;
    for (const [placeholder, value] of Object.entries(substitutions)) {
        localizedMessage = localizedMessage.replace(`$${placeholder}$`, value);
    }
    return localizedMessage;
}

async function initializeLocalization() {
    currentLanguage = navigator.language.split('-')[0] || 'en';
    window.localization = await loadLocalization(currentLanguage);
}
