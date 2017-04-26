package cryptography_project;

import java.security.InvalidKeyException;
import javax.swing.JOptionPane;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

/*
Author: Joshua Insel

RSA Decryption Panel
Decrypts user-inputted ciphertexts with user-inputted public key
Input and output are in text areas
Base64 encoding for ciphertext
*/

public class RSA_DecryptionPanel extends javax.swing.JPanel {
    private final RSA_Cipher cipher = new RSA_Cipher();
    private RSA_PrivateKey privateKey;

    public RSA_DecryptionPanel() {
        initComponents();
        plainTextArea.setEditable(false);
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
            try {
                byte[] plainTextBytes = cipher.decrypt(cipherTextBytes, privateKey);
                String plainText = new String(plainTextBytes);
                plainTextArea.setText(plainText);
            }
            catch (InvalidDataException e) {
                JOptionPane.showMessageDialog(this, "The ciphertext cannot be longer than the key. Key: " + privateKey.getModulus().bitLength() + 
                        " bits, Ciphertext: " + cipherTextBytes.length*8 + " bits.", "Too Long Ciphertext", JOptionPane.ERROR_MESSAGE);
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
        cipherTextArea = new javax.swing.JTextArea();
        jLabel1 = new javax.swing.JLabel();
        jScrollPane3 = new javax.swing.JScrollPane();
        plainTextArea = new javax.swing.JTextArea();
        plainTextLabel = new javax.swing.JLabel();
        decryptButton = new javax.swing.JButton();

        keyArea.setColumns(20);
        keyArea.setRows(5);
        jScrollPane1.setViewportView(keyArea);

        keyLabel.setText("Private Key");

        cipherTextArea.setColumns(20);
        cipherTextArea.setRows(5);
        jScrollPane2.setViewportView(cipherTextArea);

        jLabel1.setText("Ciphertext");

        plainTextArea.setColumns(20);
        plainTextArea.setRows(5);
        jScrollPane3.setViewportView(plainTextArea);

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
                .addGap(45, 45, 45)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 426, Short.MAX_VALUE)
                        .addComponent(keyLabel)
                        .addComponent(jScrollPane1))
                    .addComponent(jLabel1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 85, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 412, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(plainTextLabel))
                .addGap(32, 32, 32))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(decryptButton)
                .addGap(452, 452, 452))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addGap(115, 115, 115)
                        .addComponent(plainTextLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 154, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(26, 26, 26)
                        .addComponent(keyLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 154, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(22, 22, 22)
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 154, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(34, 34, 34)
                .addComponent(decryptButton)
                .addContainerGap(39, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void decryptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decryptButtonActionPerformed
        decrypt();
    }//GEN-LAST:event_decryptButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea cipherTextArea;
    private javax.swing.JButton decryptButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JTextArea keyArea;
    private javax.swing.JLabel keyLabel;
    private javax.swing.JTextArea plainTextArea;
    private javax.swing.JLabel plainTextLabel;
    // End of variables declaration//GEN-END:variables
}
