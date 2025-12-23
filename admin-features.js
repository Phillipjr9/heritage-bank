// ========== BANKING ADMIN FEATURES ==========

// Load dashboard statistics
async function loadDashboardStats() {
    try {
        const res = await fetch(`${API_URL}/api/admin/dashboard-stats`);
        const data = await res.json();
        if (data.success) {
            const s = data.stats;
            document.getElementById('totalUsers').textContent = s.totalUsers;
            document.getElementById('totalBalance').textContent = '$' + parseFloat(s.totalBalance).toLocaleString();
            document.getElementById('todayTransactions').textContent = s.todayTransactions;
            document.getElementById('pendingLoans').textContent = s.pendingLoans;
            document.getElementById('monthlyTransactions').textContent = s.monthlyTransactions;
            document.getElementById('activeUsers').textContent = s.activeUsers;
            document.getElementById('monthlyVolume').textContent = '$' + parseFloat(s.monthlyVolume).toLocaleString();
            document.getElementById('failedLogins').textContent = s.failedLoginsToday;
        }
    } catch (e) { console.error('Dashboard stats error:', e); }
}

// Search users
async function searchUsers() {
    const query = document.getElementById('userSearchInput').value;
    if (query.length < 2) {
        document.getElementById('userSearchResults').innerHTML = '<p style="color: #dc3545;">Please enter at least 2 characters</p>';
        return;
    }

    try {
        const res = await fetch(`${API_URL}/api/admin/search-users?query=${encodeURIComponent(query)}`);
        const data = await res.json();
        
        if (data.success && data.users.length > 0) {
            document.getElementById('userSearchResults').innerHTML = `
                <table style="width: 100%; background: white; border-radius: 8px; overflow: hidden;">
                    <thead><tr style="background: #1a472a; color: white;"><th style="padding: 12px;">Name</th><th>Email</th><th>Account</th><th>Balance</th><th>Status</th><th>Actions</th></tr></thead>
                    <tbody>${data.users.map(u => `
                        <tr style="border-bottom: 1px solid #ddd;">
                            <td style="padding: 10px;">${u.firstName} ${u.lastName}</td>
                            <td>${u.email}</td>
                            <td>${u.accountNumber}</td>
                            <td>$${parseFloat(u.balance).toLocaleString()}</td>
                            <td><span class="badge badge-${u.accountStatus === 'active' ? 'approved' : 'pending'}">${u.accountStatus}</span></td>
                            <td>
                                <button onclick="manageAccount(${u.id}, '${u.firstName} ${u.lastName}')" class="btn-view btn-sm">Manage</button>
                            </td>
                        </tr>
                    `).join('')}</tbody>
                </table>
            `;
        } else {
            document.getElementById('userSearchResults').innerHTML = '<p style="color: #999;">No users found</p>';
        }
    } catch (e) {
        document.getElementById('userSearchResults').innerHTML = `<p style="color: #dc3545;">Error: ${e.message}</p>`;
    }
}

// Search transactions
async function searchTransactions() {
    const params = new URLSearchParams();
    const accountNumber = document.getElementById('txnAccountNumber').value;
    const type = document.getElementById('txnType').value;
    const startDate = document.getElementById('txnStartDate').value;
    const endDate = document.getElementById('txnEndDate').value;
    const minAmount = document.getElementById('txnMinAmount').value;
    const maxAmount = document.getElementById('txnMaxAmount').value;

    if (accountNumber) params.append('accountNumber', accountNumber);
    if (type) params.append('type', type);
    if (startDate) params.append('startDate', startDate);
    if (endDate) params.append('endDate', endDate);
    if (minAmount) params.append('minAmount', minAmount);
    if (maxAmount) params.append('maxAmount', maxAmount);

    try {
        const res = await fetch(`${API_URL}/api/admin/search-transactions?${params}`);
        const data = await res.json();
        
        if (data.success && data.transactions.length > 0) {
            document.getElementById('txnSearchResults').innerHTML = `
                <table style="width: 100%; background: white; border-radius: 8px; overflow: hidden;">
                    <thead><tr style="background: #1a472a; color: white;"><th style="padding: 12px;">Date</th><th>Reference</th><th>From</th><th>To</th><th>Amount</th><th>Type</th><th>Status</th><th>Actions</th></tr></thead>
                    <tbody>${data.transactions.map(t => `
                        <tr style="border-bottom: 1px solid #ddd;">
                            <td style="padding: 10px;">${new Date(t.created_at).toLocaleString()}</td>
                            <td style="font-family: monospace; font-size: 0.85rem;">${t.reference}</td>
                            <td>${t.senderFirst || ''} ${t.senderLast || ''}</td>
                            <td>${t.recipientFirst || ''} ${t.recipientLast || ''}</td>
                            <td style="font-weight: bold;">$${parseFloat(t.amount).toLocaleString()}</td>
                            <td>${t.type}</td>
                            <td><span class="badge badge-${t.status === 'completed' ? 'completed' : t.status === 'reversed' ? 'rejected' : 'pending'}">${t.status}</span></td>
                            <td>
                                ${t.status === 'completed' ? `<button onclick="reverseTransaction(${t.id}, '${t.reference}')" class="btn-reject btn-sm">Reverse</button>` : ''}
                            </td>
                        </tr>
                    `).join('')}</tbody>
                </table>
            `;
        } else {
            document.getElementById('txnSearchResults').innerHTML = '<p style="color: #999;">No transactions found</p>';
        }
    } catch (e) {
        document.getElementById('txnSearchResults').innerHTML = `<p style="color: #dc3545;">Error: ${e.message}</p>`;
    }
}

// Manage account (freeze/unfreeze/close)
async function manageAccount(userId, userName) {
    const action = prompt(`Manage account for ${userName}\n\nEnter action:\n1 = Freeze Account\n2 = Unfreeze (Activate)\n3 = Suspend\n4 = Close Account\n\nEnter number (1-4):`);
    
    const statusMap = { '1': 'frozen', '2': 'active', '3': 'suspended', '4': 'closed' };
    const status = statusMap[action];
    
    if (!status) return;
    
    const reason = prompt(`Reason for ${status} status:`);
    if (!reason) return;

    try {
        const res = await fetch(`${API_URL}/api/admin/account-status/${userId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status, reason })
        });
        const data = await res.json();
        alert(data.message);
        if (data.success) { loadUsers(); searchUsers(); }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

// Reverse transaction
async function reverseTransaction(transactionId, reference) {
    if (!confirm(`Reverse transaction ${reference}?\n\nThis will refund the money to the sender.`)) return;
    
    const reason = prompt('Reason for reversal:');
    if (!reason) return;

    try {
        const res = await fetch(`${API_URL}/api/admin/reverse-transaction/${transactionId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason })
        });
        const data = await res.json();
        alert(data.message);
        if (data.success) {
            loadTransactions();
            searchTransactions();
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

// Generate monthly report
async function generateMonthlyReport() {
    const year = document.getElementById('reportYear').value;
    const month = document.getElementById('reportMonth').value;

    try {
        const res = await fetch(`${API_URL}/api/admin/monthly-report?year=${year}&month=${month}`);
        const data = await res.json();
        
        if (data.success) {
            const r = data.report;
            document.getElementById('monthlyReportContent').innerHTML = `
                <div style="background: white; padding: 20px; border-radius: 8px; margin-top: 15px;">
                    <h4 style="color: #1a472a; margin-bottom: 15px;">Report for ${r.period}</h4>
                    
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-bottom: 20px;">
                        <div style="background: #f0f8ff; padding: 15px; border-radius: 8px;">
                            <h5 style="color: #1a472a;">Transactions</h5>
                            <p style="margin: 5px 0;"><strong>Total:</strong> ${r.transactions.totalTransactions}</p>
                            <p style="margin: 5px 0;"><strong>Transfers:</strong> ${r.transactions.transfers}</p>
                            <p style="margin: 5px 0;"><strong>Bill Payments:</strong> ${r.transactions.billPayments}</p>
                            <p style="margin: 5px 0;"><strong>Deposits:</strong> ${r.transactions.deposits}</p>
                            <p style="margin: 5px 0;"><strong>Volume:</strong> $${parseFloat(r.transactions.totalVolume || 0).toLocaleString()}</p>
                            <p style="margin: 5px 0;"><strong>Avg Transaction:</strong> $${parseFloat(r.transactions.avgTransaction || 0).toLocaleString()}</p>
                        </div>
                        
                        <div style="background: #fff0f0; padding: 15px; border-radius: 8px;">
                            <h5 style="color: #1a472a;">Loans</h5>
                            <p style="margin: 5px 0;"><strong>Applications:</strong> ${r.loans.totalApplications}</p>
                            <p style="margin: 5px 0;"><strong>Approved:</strong> ${r.loans.approved}</p>
                            <p style="margin: 5px 0;"><strong>Rejected:</strong> ${r.loans.rejected}</p>
                            <p style="margin: 5px 0;"><strong>Approved Amount:</strong> $${parseFloat(r.loans.totalApproved || 0).toLocaleString()}</p>
                        </div>
                    </div>
                    
                    <div style="background: #f0fff0; padding: 15px; border-radius: 8px;">
                        <h5 style="color: #1a472a;">New Users</h5>
                        <p style="margin: 5px 0; font-size: 1.5rem; font-weight: bold;">${r.newUsers}</p>
                    </div>
                </div>
            `;
        }
    } catch (e) {
        document.getElementById('monthlyReportContent').innerHTML = `<p style="color: #dc3545;">Error: ${e.message}</p>`;
    }
}

// Export users
function exportUsers() {
    window.open(`${API_URL}/api/admin/export-users`, '_blank');
}

// Export all transactions
function exportAllTransactions() {
    const startDate = prompt('Start date (YYYY-MM-DD) - leave empty for all:');
    const endDate = prompt('End date (YYYY-MM-DD) - leave empty for all:');
    
    let url = `${API_URL}/api/admin/export-transactions`;
    const params = new URLSearchParams();
    if (startDate) params.append('startDate', startDate);
    if (endDate) params.append('endDate', endDate);
    
    if (params.toString()) url += '?' + params.toString();
    window.open(url, '_blank');
}

// Export filtered transactions
function exportTransactions() {
    window.open(`${API_URL}/api/admin/export-transactions`, '_blank');
}

// Load documents
async function loadDocuments() {
    try {
        const res = await fetch(`${API_URL}/api/admin/documents/pending`);
        const data = await res.json();
        if (data.success) {
            const tbody = document.getElementById('documentsTableBody');
            if (data.documents.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#999;">No pending documents</td></tr>';
                return;
            }
            
            tbody.innerHTML = data.documents.map(doc => `
                <tr>
                    <td>${doc.firstName} ${doc.lastName}</td>
                    <td>${doc.documentType}</td>
                    <td>${new Date(doc.submittedAt).toLocaleDateString()}</td>
                    <td><span class="badge badge-pending">${doc.verificationStatus}</span></td>
                    <td>
                        <button class="btn-view btn-sm" onclick="window.open('${doc.documentUrl}', '_blank')">View</button>
                        <button class="btn-approve btn-sm" onclick="approveDocument(${doc.id})">Approve</button>
                        <button class="btn-reject btn-sm" onclick="rejectDocument(${doc.id})">Reject</button>
                    </td>
                </tr>
            `).join('');
        }
    } catch (e) {
        console.error('Documents error:', e);
        document.getElementById('documentsTableBody').innerHTML = 
            '<tr><td colspan="5" style="text-align:center; color:#999;">Error loading documents</td></tr>';
    }
}

// Approve document
async function approveDocument(docId) {
    if (!confirm('Approve this document?')) return;

    try {
        const res = await fetch(`${API_URL}/api/admin/documents/${docId}/approve`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await res.json();
        alert(data.message);
        if (data.success) loadDocuments();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

// Reject document
async function rejectDocument(docId) {
    const reason = prompt('Reason for rejection:');
    if (!reason) return;

    try {
        const res = await fetch(`${API_URL}/api/admin/documents/${docId}/reject`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rejectionReason: reason })
        });
        const data = await res.json();
        alert(data.message);
        if (data.success) loadDocuments();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

// Update the initialization
function initializeAdminFeatures() {
    loadDashboardStats();
    loadDocuments();
    
    // Auto-refresh advanced features
    const originalInterval = setInterval;
    setTimeout(() => {
        const refreshInterval = setInterval(() => {
            loadDashboardStats();
            loadDocuments();
        }, 30000);
    }, 1000);
}

// Call initialization when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAdminFeatures);
} else {
    initializeAdminFeatures();
}
