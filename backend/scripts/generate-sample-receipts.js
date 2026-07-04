const fs = require('fs');
const path = require('path');
const ReceiptGenerator = require('../pdf-receipt-generator');

async function makeSamples() {
  const outDir = path.resolve(__dirname, '..', 'sample-receipts');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  const user = { id: 42, firstName: 'Jane', lastName: 'Doe', email: 'jane.doe@example.com', accountNumber: '1234567890' };

  const samples = [
    {
      id: 1001,
      reference: 'TXN-1001',
      createdAt: new Date().toISOString(),
      status: 'completed',
      type: 'admin_credit',
      amount: 1500.0,
      fee: 0,
      fromUserId: 1,
      toUserId: 42,
      fromUserEmail: 'admin@heritage.com',
      fromFirstName: '',
      fromLastName: '',
      toFirstName: 'Jane',
      toLastName: 'Doe',
      toAccountNumber: '9876543210',
      recipientName: 'Jane Doe',
      description: 'Direct Deposit | From: Payroll Dept',
      fromLabel: 'Payroll Dept'
    },
    {
      id: 1002,
      reference: 'TXN-1002',
      createdAt: new Date().toISOString(),
      status: 'completed',
      type: 'transfer',
      amount: -250.75,
      fee: 2.5,
      fromUserId: 42,
      toUserId: 99,
      fromUserEmail: 'jane.doe@example.com',
      fromFirstName: 'Jane',
      fromLastName: 'Doe',
      fromAccountNumber: '1234567890',
      toFirstName: 'Bob',
      toLastName: 'Smith',
      toAccountNumber: '444433332222',
      recipientName: 'Bob Smith',
      description: 'Payment for invoice #4532'
    },
    {
      id: 1003,
      reference: 'TXN-1003',
      createdAt: new Date().toISOString(),
      status: 'completed',
      type: 'wire_transfer',
      amount: -1200.0,
      fee: 15.0,
      fromUserId: 42,
      toUserId: null,
      fromUserEmail: 'jane.doe@example.com',
      fromFirstName: 'Jane',
      fromLastName: 'Doe',
      fromAccountNumber: '1234567890',
      toFirstName: '',
      toLastName: '',
      toAccountNumber: '0000111122223333',
      recipientName: 'ACME Corp International',
      destinationCountry: 'GB',
      exchangeRate: '1.25',
      recipientAmount: '960.00',
      recipientCurrency: 'GBP',
      description: 'UK Bank Transfer to ACME Ltd | Recipient: ACME Corp International'
    }
  ];

  for (const s of samples) {
    try {
      const buf = await ReceiptGenerator.generate(s, user);
      const filename = path.join(outDir, `${s.reference || 'receipt-' + s.id}.pdf`);
      fs.writeFileSync(filename, buf);
      console.log('Written:', filename);
    } catch (e) {
      console.error('Failed to generate sample', s.reference, e);
    }
  }
}

makeSamples().catch(e => {
  console.error(e);
  process.exit(1);
});
