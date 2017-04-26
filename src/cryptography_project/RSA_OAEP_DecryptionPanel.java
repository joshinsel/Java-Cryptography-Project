package cryptography_project;

import java.security.InvalidKeyException;
import javax.swing.JOptionPane;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

/*
Author: Joshua Insel

RSA-OAEP Decryption Panel
Decrypts user-inputted ciphertexts with user-inputted public key
Input and output are in text areas
Base64 encoding for ciphertext
*/

public class RSA_OAEP_DecryptionPanel extends javax.swing.JPanel {
    private final RSA_Cipher cipher = new RSA_Cipher();
    private RSA_PrivateKey privateKey;

    public RSA_OAEP_DecryptionPanel() {
        initComponents();
        setSize(1000, 500);
    }
    
    private void decodeKey() throws InvalidKeyException {
        ASN1Sequence sequence;
        if (keyArea.getText().trim().equals("")) {
            JOptionPane.showMessageDialog(this, "The key field is blank.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
            throw new InvalidKeyException();
        }
        try {
            sequence = ASN1Sequence.getInstance(Base64.decodeBase64(keyArea.getText().trim()));
            if (sequence == null) {
                JOptionPane.showMessageDialog(this, "Not a valid RSA public key.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
                throw new InvalidKeyException();
            }
            ASN1Encodable[] integers = sequence.toArray();
            if (integers.length != 2) {
                JOptionPane.showMessageDialog(this, "Not a valid RSA private key.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
                throw new InvalidKeyException();
            }
            else {
                ASN1Integer modulus = null;
                ASN1Integer privateExponent = null;
                try {
                    modulus = (ASN1Integer) integers[0];
                    privateExponent = (ASN1Integer) integers[1];
                }
                catch (ClassCastException e) {
                    JOptionPane.showMessageDialog(this, "Not a valid RSA private key.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
                    throw new InvalidKeyException();
                }
                try {
                    privateKey = new RSA_PrivateKey(modulus.getValue(), privateExponent.getValue());
                }
                catch (InvalidKeyException e) {
                    JOptionPane.showMessageDialog(this, "The private exponent must be less than the modulus.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
                    throw new InvalidKeyException();
                }
            }
        }
        catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this, "Not a valid RSA private key.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
            throw new InvalidKeyException();
        }
    }
    
    private void decrypt() {
        try {
            decodeKey();
            if (cipherTextArea.getText().trim().equals("")) {
                JOptionPane.showMessageDialog(this, "The ciphertext field is blank.", "Invalid Ciphertext", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String cipherText = cipherTextArea.getText().trim();
            byte[] cipherTextBytes = Base64.decodeBase64(cipherText);
            String label = labelArea.getText().trim();
            byte[] labelBytes = label.getBytes();
            try {
                byte[] plainTextBytes = cipher.decryptOAEP(cipherTextBytes, labelBytes, privateKey);
                String plainText = new String(plainTextBytes);
                plainTextArea.setText(plainText);
            }
            catch (InvalidDataException e) {
                JOptionPane.showMessageDialog(this, "The ciphertext cannot be longer than the key. Key: " + privateKey.getModulus().bitLength() + 
                        " bits, Ciphertext: " + cipherTextBytes.length*8 + " bits.", "Too Long Ciphertext", JOptionPane.ERROR_MESSAGE);
            }
            catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(this, "Decryption error. Not a valid RSA-OAEP ciphertext.", "Invalid Ciphertext", JOptionPane.ERROR_MESSAGE);
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
        cipherTextLabel = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        cipherTextArea = new javax.swing.JTextArea();
        labelLabel = new javax.swing.JLabel();
        jScrollPane4 = new javax.swing.JScrollPane();
        plainTextArea = new javax.swing.JTextArea();
        plainTextLabel = new javax.swing.JLabel();
        labelArea = new javax.swing.JTextField();
        decryptButton = new javax.swing.JButton();

        keyArea.setColumns(20);
        keyArea.setRows(5);
        jScrollPane1.setViewportView(keyArea);

        keyLabel.setText("Private Key");

        cipherTextLabel.setText("Ciphertext");

        cipherTextArea.setColumns(20);
        cipherTextArea.setRows(5);
        jScrollPane2.setViewportView(cipherTextArea);

        labelLabel.setText("Label (must be the same as during encryption):");

        plainTextArea.setColumns(20);
        plainTextArea.setRows(5);
        jScrollPane4.setViewportView(plainTextArea);

        plainTextLabel.setText("Plaintext");

        decryptButton.setText("Decrypt");
        decryptButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decryptButtonActionPerformed(evt);
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
                        .addGap(443, 443, 443)
                        .addComponent(decryptButton)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 425, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(cipherTextLabel)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 425, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 426, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(plainTextLabel))
                        .addGap(39, 39, 39))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(keyLabel)
                            .addComponent(labelLabel)
                            .addComponent(labelArea, javax.swing.GroupLayout.PREFERRED_SIZE, 425, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(24, 24, 24)
                .addComponent(keyLabel)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 153, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(cipherTextLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 156, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(82, 82, 82)
                        .addComponent(plainTextLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 154, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(labelLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(labelArea, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(32, 32, 32))
                    .addComponent(decryptButton))
                .addContainerGap(30, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void decryptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decryptButtonActionPerformed
        decrypt();
    }//GEN-LAST:event_decryptButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea cipherTextArea;
    private javax.swing.JLabel cipherTextLabel;
    private javax.swing.JButton decryptButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JTextArea keyArea;
    private javax.swing.JLabel keyLabel;
    private javax.swing.JTextField labelArea;
    private javax.swing.JLabel labelLabel;
    private javax.swing.JTextArea plainTextArea;
    private javax.swing.JLabel plainTextLabel;
    // End of variables declaration//GEN-END:variables
}
