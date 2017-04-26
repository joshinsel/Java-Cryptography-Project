package cryptography_project;

import java.security.InvalidKeyException;
import javax.swing.JOptionPane;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.*;

/*
Author: Joshua Insel

RSA Encryption Panel
Encrypts user-inputted plaintexts with user-inputted public key
Input and output are in text areas
Base64 encoding for ciphertext
*/

public class RSA_EncryptionPanel extends javax.swing.JPanel {
    private final RSA_Cipher cipher = new RSA_Cipher();
    private RSA_PublicKey publicKey;
    

    public RSA_EncryptionPanel() {
        initComponents();
        cipherTextArea.setEditable(false);
        setSize(1000, 500);
    }
    
    private void decodeKey() throws InvalidKeyException {
        if (keyArea.getText().trim().equals("")) {
            JOptionPane.showMessageDialog(this, "The key field is blank.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
            throw new InvalidKeyException();
        }
        ASN1Sequence sequence;
        try {
            sequence = ASN1Sequence.getInstance(Base64.decodeBase64(keyArea.getText().trim()));
            if (sequence == null) {
                JOptionPane.showMessageDialog(this, "Not a valid RSA public key.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
                throw new InvalidKeyException();
            }
            ASN1Encodable[] integers = sequence.toArray();
            if (integers.length != 2) {
                JOptionPane.showMessageDialog(this, "Not a valid RSA public key.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
                throw new InvalidKeyException();
            }
            else {
                ASN1Integer modulus = null;
                ASN1Integer publicExponent = null;
                try {
                    modulus = (ASN1Integer) integers[0];
                    publicExponent = (ASN1Integer) integers[1];
                }
                catch (ClassCastException e) {
                    JOptionPane.showMessageDialog(this, "Not a valid RSA public key.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
                    throw new InvalidKeyException();
                }
                try {
                    publicKey = new RSA_PublicKey(modulus.getValue(), publicExponent.getValue());
                }
                catch (InvalidKeyException e) {
                    JOptionPane.showMessageDialog(this, "The public exponent must be between 3 and the modulus.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
                    throw new InvalidKeyException();
                }
            }
        }
        catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this, "Not a valid RSA public key.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
            throw new InvalidKeyException();
        }
    }
    
    private void encrypt() {
        try {
            decodeKey();
            if (plainTextArea.getText().trim().equals("")) {
                JOptionPane.showMessageDialog(this, "The plaintext field is blank.", "Invalid Plaintext", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String plainText = plainTextArea.getText().trim();
            byte[] plainTextBytes = plainText.getBytes();
            try {
                byte[] cipherTextBytes = cipher.encrypt(plainTextBytes, publicKey);
                String cipherText = Base64.encodeBase64String(cipherTextBytes);
                cipherTextArea.setText(cipherText);
            }
            catch (InvalidDataException e) {
                JOptionPane.showMessageDialog(this, "The plaintext cannot be longer than the key. Key: " + publicKey.getModulus().bitLength() + " bits, Plaintext: " + 
                        plainTextBytes.length*8 + " bits.", "Too Long Plaintext", JOptionPane.ERROR_MESSAGE);
            }
        }
        catch (InvalidKeyException e) {}
    }
    

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        keyArea = new javax.swing.JTextArea();
        keyLabel = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        plainTextArea = new javax.swing.JTextArea();
        plainTextLabel = new javax.swing.JLabel();
        jScrollPane3 = new javax.swing.JScrollPane();
        cipherTextArea = new javax.swing.JTextArea();
        cipherTextLabel = new javax.swing.JLabel();
        encryptButton = new javax.swing.JButton();

        keyArea.setColumns(20);
        keyArea.setRows(5);
        jScrollPane1.setViewportView(keyArea);

        keyLabel.setText("Public Key");

        plainTextArea.setColumns(20);
        plainTextArea.setRows(5);
        jScrollPane2.setViewportView(plainTextArea);

        plainTextLabel.setText("Plaintext");

        cipherTextArea.setColumns(20);
        cipherTextArea.setRows(5);
        jScrollPane3.setViewportView(cipherTextArea);

        cipherTextLabel.setText("Ciphertext");

        encryptButton.setText("Encrypt");
        encryptButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encryptButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(40, 40, 40)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(keyLabel)
                    .addComponent(plainTextLabel)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 422, Short.MAX_VALUE)
                    .addComponent(jScrollPane1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 98, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(cipherTextLabel)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 419, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(21, 21, 21))
            .addGroup(layout.createSequentialGroup()
                .addGap(456, 456, 456)
                .addComponent(encryptButton)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(30, 30, 30)
                .addComponent(keyLabel)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 159, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(6, 6, 6)
                        .addComponent(plainTextLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 172, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(61, 61, 61)
                        .addComponent(cipherTextLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 177, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(36, 36, 36)
                .addComponent(encryptButton)
                .addContainerGap(26, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void encryptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encryptButtonActionPerformed
        encrypt();
    }//GEN-LAST:event_encryptButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea cipherTextArea;
    private javax.swing.JLabel cipherTextLabel;
    private javax.swing.JButton encryptButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JTextArea keyArea;
    private javax.swing.JLabel keyLabel;
    private javax.swing.JTextArea plainTextArea;
    private javax.swing.JLabel plainTextLabel;
    // End of variables declaration//GEN-END:variables
}
