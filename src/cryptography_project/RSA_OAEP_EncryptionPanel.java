package cryptography_project;

import java.security.InvalidKeyException;
import javax.swing.JOptionPane;
import org.apache.commons.codec.binary.*;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

/*
Author: Joshua Insel

RSA-OAEP Encryption Panel
Encrypts user-inputted plaintexts with user-inputted public key
Input and output are in text areas
Base64 encoding for ciphertext
*/

public class RSA_OAEP_EncryptionPanel extends javax.swing.JPanel {
    private final RSA_Cipher cipher = new RSA_Cipher();
    private RSA_PublicKey publicKey;
    
    public RSA_OAEP_EncryptionPanel() {
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
            String label = labelArea.getText().trim();
            byte[] labelBytes = label.getBytes();
            try {
                byte[] cipherTextBytes = cipher.encryptOAEP(plainTextBytes, labelBytes, publicKey);
                String cipherText = Base64.encodeBase64String(cipherTextBytes);
                cipherTextArea.setText(cipherText);
            }
            catch (InvalidDataException e) {
                JOptionPane.showMessageDialog(this, "The plaintext cannot be longer than " + (publicKey.getModulus().bitLength() - 528) + " bits.", "Too Long Plaintext", JOptionPane.ERROR_MESSAGE);
            }
        }
        catch (InvalidKeyException e) {}
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        keyArea = new javax.swing.JTextArea();
        publicKeyLabel = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        plainTextArea = new javax.swing.JTextArea();
        labelLabel = new javax.swing.JLabel();
        jScrollPane4 = new javax.swing.JScrollPane();
        cipherTextArea = new javax.swing.JTextArea();
        cipherTextLabel = new javax.swing.JLabel();
        encryptButton = new javax.swing.JButton();
        labelArea = new javax.swing.JTextField();

        keyArea.setColumns(20);
        keyArea.setRows(5);
        jScrollPane1.setViewportView(keyArea);

        publicKeyLabel.setText("Public Key");

        jLabel1.setText("Plaintext");

        plainTextArea.setColumns(20);
        plainTextArea.setRows(5);
        jScrollPane2.setViewportView(plainTextArea);

        labelLabel.setText("Label (optional)");

        cipherTextArea.setColumns(20);
        cipherTextArea.setRows(5);
        jScrollPane4.setViewportView(cipherTextArea);

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
                .addGap(31, 31, 31)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(labelLabel)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(labelArea, javax.swing.GroupLayout.DEFAULT_SIZE, 420, Short.MAX_VALUE)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                .addComponent(jScrollPane2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 420, Short.MAX_VALUE)
                                .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(publicKeyLabel, javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING)))
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 110, Short.MAX_VALUE)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 419, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(cipherTextLabel))
                                .addGap(20, 20, 20))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(33, 33, 33)
                                .addComponent(encryptButton)
                                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(encryptButton)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(publicKeyLabel)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 161, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(jLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 160, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(96, 96, 96)
                                .addComponent(cipherTextLabel)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 160, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(labelLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(labelArea, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(31, 31, 31)))
                .addContainerGap(56, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void encryptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encryptButtonActionPerformed
        encrypt();
    }//GEN-LAST:event_encryptButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea cipherTextArea;
    private javax.swing.JLabel cipherTextLabel;
    private javax.swing.JButton encryptButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JTextArea keyArea;
    private javax.swing.JTextField labelArea;
    private javax.swing.JLabel labelLabel;
    private javax.swing.JTextArea plainTextArea;
    private javax.swing.JLabel publicKeyLabel;
    // End of variables declaration//GEN-END:variables
}
