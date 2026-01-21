let allEmails = {};
let currentCategory = null;

document.addEventListener('DOMContentLoaded', () => {
    loadEmails();
});

function loadEmails() {
    const emailsContainer = document.getElementById('emailsContainer');
    emailsContainer.innerHTML = '<div class="loading">Loading emails...</div>';

    fetch('/api/emails')
        .then(response => response.json())
        .then(data => {
            allEmails = data;
            displayCategories();
            if (Object.keys(data).length > 0) {
                currentCategory = Object.keys(data)[0];
                displayEmailsByCategory(currentCategory);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            emailsContainer.innerHTML = '<div class="error">Error loading emails</div>';
        });
}

function displayCategories() {
    const categoriesList = document.getElementById('categoriesList');
    categoriesList.innerHTML = '';

    Object.keys(allEmails).forEach(category => {
        const btn = document.createElement('button');
        btn.className = 'category-btn';
        btn.textContent = `${category} (${allEmails[category].length})`;
        btn.onclick = () => {
            document.querySelectorAll('.category-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentCategory = category;
            displayEmailsByCategory(category);
        };
        if (category === currentCategory) {
            btn.classList.add('active');
        }
        categoriesList.appendChild(btn);
    });
}

function displayEmailsByCategory(category) {
    const emailsContainer = document.getElementById('emailsContainer');
    emailsContainer.innerHTML = '';

    const emails = allEmails[category] || [];
    
    emails.forEach(email => {
        const card = document.createElement('div');
        card.className = 'email-card';
        card.innerHTML = `
            <div class="email-card-header">
                <span class="email-from">${email.from}</span>
                <span class="email-category">${email.category}</span>
            </div>
            <div class="email-subject">${email.subject}</div>
        `;
        card.onclick = () => openEmail(email.id);
        emailsContainer.appendChild(card);
    });
}

function openEmail(emailId) {
    fetch(`/api/open-email/${emailId}`)
        .then(response => response.json())
        .then(data => {
            window.open(data.url, '_blank');
        });
}
