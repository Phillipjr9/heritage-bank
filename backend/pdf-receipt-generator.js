/**
 * Heritage Bank - Professional PDF Receipt Generator
 * Generates branded, professional receipts for transactions
 */

const PDFDocument = require('pdfkit');
const { Readable } = require('stream');
const fs = require('fs');
const path = require('path');

class ReceiptGenerator {
  static generate(transaction, user, options = {}) {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({
          size: 'A4',
          margin: 40
        });

        let chunks = [];
        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);

        // Document metadata
        doc.info = doc.info || {};
        doc.info.Title = `Transaction Receipt - ${transaction.reference || `TXN-${transaction.id}`}`;
        doc.info.Author = 'Heritage Bank';
        doc.info.Subject = 'Transaction Receipt';
        doc.info.Keywords = 'heritage, receipt, transaction';

        // Header with optional logo and company info
        const logoPath = path.resolve(__dirname, '..', 'assets', 'bank-logos', 'logo.png');
        let hasLogo = false;
        try {
          hasLogo = fs.existsSync(logoPath);
          if (hasLogo) {
            // place logo at top-left
            doc.image(logoPath, 50, 50, { width: 100 });
          }
        } catch (e) {
          hasLogo = false;
        }

        // If no logo image, draw a simple vector brand mark
        if (!hasLogo) {
          // green circle with HB initials
          doc.save();
          doc.circle(90, 70, 28).fill('#0f5132');
          doc.fillColor('#fff').font('Helvetica-Bold').fontSize(18).text('HB', 78, 56);
          doc.restore();
        }

        // Bank title and short info to the right of logo
        const headerStartY = 55;
        const headerX = hasLogo ? 160 : 140;
        doc.fontSize(20).font('Helvetica-Bold').fillColor('#0f5132').text('Heritage Bank', headerX, headerStartY);
        doc.moveDown(0.2);
        doc.fontSize(9).font('Helvetica').fillColor('#666').text('Professional Banking Solutions', { align: 'left' });
        doc.fontSize(8).fillColor('#777').text('Member FDIC | Equal Housing Lender', { align: 'left' });

        // Company contact info below header
        doc.moveTo(50, doc.y + 12).lineTo(550, doc.y + 12).stroke('#eee');
        doc.fontSize(9).fillColor('#666');
        doc.text('Heritage Bank Headquarters — 123 Heritage Way, Anytown, USA', 50, doc.y + 8);
        doc.text('contact@heritagebank.com | 1-800-HERITAGE | www.heritagebank.com', 50);
        doc.moveTo(50, doc.y + 8).lineTo(550, doc.y + 8).stroke('#eee');

        // Transaction header
        doc.fontSize(14).font('Helvetica-Bold').fillColor('#1a472a').text('TRANSACTION RECEIPT', 50, doc.y + 20);

        // Transaction details in two columns
        const leftX = 50;
        const rightX = 300;
        const detailY = doc.y + 15;

        doc.fontSize(10).font('Helvetica-Bold').fillColor('#333');
        doc.text('Reference Number:', leftX, detailY);
        doc.fontSize(10).font('Helvetica').fillColor('#666').text(transaction.reference || `TXN-${transaction.id}`, rightX, detailY);

        doc.fontSize(10).font('Helvetica-Bold').fillColor('#333').text('Transaction Date:', leftX, doc.y + 15);
        doc.fontSize(10).font('Helvetica').fillColor('#666').text(this.formatDate(transaction.createdAt), rightX, doc.y - 15);

        doc.fontSize(10).font('Helvetica-Bold').fillColor('#333').text('Transaction Time:', leftX, doc.y + 15);
        doc.fontSize(10).font('Helvetica').fillColor('#666').text(this.formatTime(transaction.createdAt), rightX, doc.y - 15);

        doc.fontSize(10).font('Helvetica-Bold').fillColor('#333').text('Status:', leftX, doc.y + 15);
        const statusColor = transaction.status === 'completed' ? '#28a745' : '#f39c12';
        doc.fontSize(10).font('Helvetica-Bold').fillColor(statusColor).text(this.capitalizeFirst(transaction.status), rightX, doc.y - 15);

        doc.moveTo(50, doc.y + 15).lineTo(550, doc.y + 15).stroke('#ddd');

        // Transaction type and amount section
        doc.fontSize(12).font('Helvetica-Bold').fillColor('#1a472a').text('TRANSACTION AMOUNT', 50, doc.y + 20);

        doc.fontSize(11).font('Helvetica').fillColor('#666').text(`Type: ${this.cleanType(transaction.type)}`, 50, doc.y + 10);

        const amountColor = transaction.type === 'credit' || transaction.toUserId === user.id ? '#28a745' : '#dc3545';
        const sign = transaction.type === 'credit' || transaction.toUserId === user.id ? '+' : '-';
        
        doc.fontSize(18).font('Helvetica-Bold').fillColor(amountColor).text(
          `${sign}$${parseFloat(transaction.amount).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`,
          50,
          doc.y + 15
        );

        if (transaction.fee && parseFloat(transaction.fee) > 0) {
          doc.fontSize(10).font('Helvetica').fillColor('#666').text(
            `Transaction Fee: -$${parseFloat(transaction.fee).toLocaleString('en-US', { minimumFractionDigits: 2 })}`,
            50,
            doc.y + 10
          );
          const total = Math.abs(parseFloat(transaction.amount)) + parseFloat(transaction.fee);
          doc.fontSize(11).font('Helvetica-Bold').fillColor('#333').text(
            `Total: -$${total.toLocaleString('en-US', { minimumFractionDigits: 2 })}`,
            50,
            doc.y + 10
          );
        }

        doc.moveTo(50, doc.y + 15).lineTo(550, doc.y + 15).stroke('#ddd');

        // Parties involved
        doc.fontSize(12).font('Helvetica-Bold').fillColor('#1a472a').text('TRANSACTION DETAILS', 50, doc.y + 20);

        // Resolve sender and recipient robustly
        let senderName = null;
        let senderAcct = null;
        let recipientName = null;
        let recipientAcct = null;

        const txFromId = transaction.fromUserId != null ? Number(transaction.fromUserId) : null;
        const txToId = transaction.toUserId != null ? Number(transaction.toUserId) : null;
        const meId = user && user.id != null ? Number(user.id) : null;

        // If user is the sender
        if (meId && txFromId === meId) {
          senderName = `${user.firstName || ''} ${user.lastName || ''}`.trim() || (user.email || 'You');
          senderAcct = user.accountNumber;
          recipientName = transaction.recipientName || `${transaction.toFirstName || ''} ${transaction.toLastName || ''}`.trim() || 'Recipient';
          recipientAcct = transaction.toAccountNumber;
        } else if (meId && txToId === meId) {
          // user is the recipient
          recipientName = `${user.firstName || ''} ${user.lastName || ''}`.trim() || (user.email || 'You');
          recipientAcct = user.accountNumber;
          senderName = transaction.fromLabel || transaction.fromName || `${transaction.fromFirstName || ''} ${transaction.fromLastName || ''}`.trim() || transaction.fromUserEmail || 'Sender';
          senderAcct = transaction.fromAccountNumber;
        } else {
          // fallback: prefer explicit fields
          senderName = transaction.fromLabel || `${transaction.fromFirstName || ''} ${transaction.fromLastName || ''}`.trim() || transaction.fromUserEmail || 'Sender';
          senderAcct = transaction.fromAccountNumber || null;
          recipientName = transaction.recipientName || `${transaction.toFirstName || ''} ${transaction.toLastName || ''}`.trim() || transaction.toUserEmail || 'Recipient';
          recipientAcct = transaction.toAccountNumber || null;
        }

        // If description contains "| From: ..." (admin helper), prefer that as label for sender
        try {
          const descMatch = String(transaction.description || '').match(/\|\s*From:\s*([^|]+)/i);
          if (descMatch && descMatch[1]) {
            senderName = descMatch[1].trim();
          }
        } catch (e) { /* ignore */ }

        // sanitize description for printing (remove admin label tags)
        let printableDescription = String(transaction.description || 'N/A').replace(/\|\s*From:\s*[^|]+/i, '').trim();

        doc.fontSize(10).font('Helvetica-Bold').fillColor('#333').text('From Account:', 50, doc.y + 10);
        doc.fontSize(10).font('Helvetica').fillColor('#666').text(`${senderName || 'Sender'}`, 50, doc.y + 5);
        if (senderAcct) {
          doc.fontSize(9).fillColor('#999').text(`Account: ****${String(senderAcct).slice(-4)}`);
        }

        doc.fontSize(10).font('Helvetica-Bold').fillColor('#333').text('To Account:', 50, doc.y + 10);
        doc.fontSize(10).font('Helvetica').fillColor('#666').text(`${recipientName || 'Recipient'}`, 50, doc.y + 5);
        if (recipientAcct) {
          doc.fontSize(9).fillColor('#999').text(`Account: ****${String(recipientAcct).slice(-4)}`);
        }

        doc.fontSize(10).font('Helvetica-Bold').fillColor('#333').text('Description:', 50, doc.y + 15);
        doc.fontSize(10).font('Helvetica').fillColor('#666').text(
          printableDescription || 'N/A',
          50,
          doc.y + 5,
          { width: 450 }
        );

        // Additional info if international
        if (transaction.destinationCountry || transaction.exchangeRate) {
          doc.moveTo(50, doc.y + 15).lineTo(550, doc.y + 15).stroke('#ddd');
          doc.fontSize(12).font('Helvetica-Bold').fillColor('#1a472a').text('INTERNATIONAL TRANSFER DETAILS', 50, doc.y + 20);

          if (transaction.destinationCountry) {
            doc.fontSize(10).font('Helvetica-Bold').fillColor('#333').text('Destination Country:', 50, doc.y + 10);
            doc.fontSize(10).font('Helvetica').fillColor('#666').text(transaction.destinationCountry, 50, doc.y + 5);
          }

          if (transaction.exchangeRate) {
            doc.fontSize(10).font('Helvetica-Bold').fillColor('#333').text('Exchange Rate:', 50, doc.y + 15);
            doc.fontSize(10).font('Helvetica').fillColor('#666').text(transaction.exchangeRate, 50, doc.y + 5);
          }

          if (transaction.recipientAmount) {
            doc.fontSize(10).font('Helvetica-Bold').fillColor('#333').text('Recipient Receives:', 50, doc.y + 15);
            const cur = transaction.recipientCurrency || 'USD';
            doc.fontSize(10).font('Helvetica').fillColor('#666').text(
              `${transaction.recipientAmount} ${cur}`,
              50,
              doc.y + 5
            );
          }
        }

        // Footer: fixed at bottom of the page
        const footerY = doc.page.height - doc.page.margins.bottom - 40;
        doc.moveTo(50, footerY).lineTo(doc.page.width - 50, footerY).stroke('#ddd');
        doc.fontSize(8).fillColor('#999').text(
          'This is an official receipt from Heritage Bank. Please keep for your records.',
          50,
          footerY + 8,
          { align: 'center', width: doc.page.width - 100 }
        );

        doc.fontSize(7).fillColor('#bbb').text(
          `Generated on ${new Date().toLocaleString('en-US')} | Confidential - For Account Holder Only`,
          50,
          footerY + 22,
          { align: 'center', width: doc.page.width - 100 }
        );

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  static formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  }

  static formatTime(dateStr) {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  }

  static capitalizeFirst(str) {
    return str ? str.charAt(0).toUpperCase() + str.slice(1).toLowerCase() : 'N/A';
  }

  static cleanType(type) {
    const map = {
      'direct_deposit': 'Direct Deposit',
      'admin_transfer': 'Transfer',
      'admin_debit': 'Debit',
      'admin_credit': 'Credit',
      'wire_transfer': 'Wire Transfer',
      'bank_transfer': 'Bank Transfer',
      'bill_payment': 'Bill Payment',
      'transfer': 'Transfer',
      'credit': 'Credit',
      'debit': 'Debit'
    };
    return map[(type || '').toLowerCase()] || this.capitalizeFirst(type);
  }
}

module.exports = ReceiptGenerator;
