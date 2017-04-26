package cryptography_project;

import java.security.InvalidKeyException;
import javax.swing.ButtonGroup;
import javax.swing.JOptionPane;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.*;

/*
Author: Joshua Insel

AES Text Encryption/Decryption Panel
Encrypts user-inputted plaintexts and decrypts user-inputted ciphertexts with AES or enhanced AES
Input and output are in text areas
Choice of Hex or Base64 encoding for keys and ciphertext (must match the input)
*/

public class AES_Text extends javax.swing.JPanel {
    private final AES_Cipher cipher = new AES_Cipher();
    private final AES_InvCipher invCipher = new AES_InvCipher();
    private final AES_EnhancedCipher enhancedCipher = new AES_EnhancedCipher();
    private final AES_EnhancedInvCipher enhancedInvCipher = new AES_EnhancedInvCipher();
    private final AES_Key key = new AES_Key();
    private final ButtonGroup aesButtons = new ButtonGroup();
    private final ButtonGroup modeButtons = new ButtonGroup();
    
    public AES_Text() {
        initComponents();
        aesButtons.add(aesButton);
        aesButtons.add(enhancedAESButton);
        modeButtons.add(encryptButton);
        modeButtons.add(decryptButton);
        setSize(1000, 500);
    }
    
    private void decodeKey() throws InvalidKeyException {  
        String keyText = keyArea.getText().trim();
        byte[] keyBytes;
        if (((String) byteEncoding.getSelectedItem()).equals("Hex")) {
            try {
                keyBytes = Hex.decodeHex(keyText.toCharArray());
                if (keyBytes.length != 16 && enhancedAESButton.isSelected()) {
                    JOptionPane.showMessageDialog(this, "A key for enhanced AES must be 128 bits.", "Invalid Key Length", JOptionPane.ERROR_MESSAGE);
                    throw new InvalidKeyException();
                }
                else {
                    try {
                        key.setKey(keyBytes);
                    }
                    catch (InvalidKeyException e) {
                        JOptionPane.showMessageDialog(this, "A key for AES must be 128, 192, or 256 bits.", "Invalid Key Length", JOptionPane.ERROR_MESSAGE);
                        throw new InvalidKeyException();
                    }
                }
            } 
            catch (DecoderException ex) {
                JOptionPane.showMessageDialog(this, "Not a valid hex string for key.", "Invalid Key Hex String", JOptionPane.ERROR_MESSAGE);
                throw new InvalidKeyException();
            }
        }
        else {
            keyBytes = Base64.decodeBase64(keyText);
            if (keyBytes.length != 16 && enhancedAESButton.isSelected()) {
                JOptionPane.showMessageDialog(this, "A key for enhanced AES must be 128 bits.", "Invalid Key Length", JOptionPane.ERROR_MESSAGE);
                throw new InvalidKeyException();
            }
            else {
                try {
                    key.setKey(keyBytes);
                }
                catch (InvalidKeyException e) {
                    JOptionPane.showMessageDialog(this, "A key for AES must be 128, 192, or 256 bits.", "Invalid Key Length", JOptionPane.ERROR_MESSAGE);
                    throw new InvalidKeyException();
                }
            }
        }
    }
    
    private void encrypt() {
        try {
            decodeKey();
            String plainText = plainTextArea.getText().trim();
            byte[] plainTextBytes = plainText.getBytes();
            byte[] cipherTextBytes = null;
            if (aesButton.isSelected()) {
                switch ((String) cipherMode.getSelectedItem()) {
                    case "ECB":
                        cipherTextBytes = cipher.encryptECB(plainTextBytes, key);
                        break;
                    case "CBC":
                        cipherTextBytes = cipher.encryptCBC(plainTextBytes, key);
                        break;
                    case "CFB":
                        cipherTextBytes = cipher.encryptCFB(plainTextBytes, key);
                        break;
                    case "OFB":
                        cipherTextBytes = cipher.encryptOFB(plainTextBytes, key);
                        break;
                }
            }
            else {
                switch ((String) cipherMode.getSelectedItem()) {
                    case "ECB":
                        cipherTextBytes = enhancedCipher.encryptECB(plainTextBytes, key);
                        break;
                    case "CBC":
                        cipherTextBytes = enhancedCipher.encryptCBC(plainTextBytes, key);
                        break;
                    case "CFB":
                        cipherTextBytes = enhancedCipher.encryptCFB(plainTextBytes, key);
                        break;
                    case "OFB":
                        cipherTextBytes = enhancedCipher.encryptOFB(plainTextBytes, key);
                        break;
                }
            }
            String cipherText;
            if (((String) byteEncoding.getSelectedItem()).equals("Hex")) {
                cipherText = Hex.encodeHexString(cipherTextBytes);
                cipherTextArea.setText(cipherText);
            } 
            else {
                cipherText = Base64.encodeBase64String(cipherTextBytes);
                cipherTextArea.setText(cipherText);
            }
        }
        catch (InvalidKeyException e) {}
    }
    
    private void decrypt() {
        try {
            decodeKey();
            if (cipherTextArea.getText().trim().equals("")) {
                JOptionPane.showMessageDialog(this, "The ciphertext field is blank.", "Invalid Ciphertext", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String cipherText = cipherTextArea.getText().trim();
            byte[] cipherTextBytes = null;
            try {
                if (((String) byteEncoding.getSelectedItem()).equals("Hex")) {
                    cipherTextBytes = Hex.decodeHex(cipherText.toCharArray());
                } 
                else {
                    cipherTextBytes = Base64.decodeBase64(cipherText);
                }
            } 
            catch (DecoderException e) {
                JOptionPane.showMessageDialog(this, "Not a valid hex string for ciphertext.", "Invalid Ciphertext Hex String", JOptionPane.ERROR_MESSAGE);
                return;
            }
            byte[] plainTextBytes = null;
            if (aesButton.isSelected()) {
                switch ((String) cipherMode.getSelectedItem()) {
                    case "ECB":
                        try {
                            plainTextBytes = invCipher.decryptECB(cipherTextBytes, key);
                        } 
                        catch (InvalidDataException e) {
                            JOptionPane.showMessageDialog(this, "This ciphertext is either an invalid length or not padded correctly.", "Invalid Ciphertext", JOptionPane.ERROR_MESSAGE);
                            return;
                        }
                        break;
                    case "CBC":
                        try {
                            plainTextBytes = invCipher.decryptCBC(cipherTextBytes, key);
                        } 
                        catch (InvalidDataException e) {
                            JOptionPane.showMessageDialog(this, "This ciphertext is either an invalid length or not padded correctly.", "Invalid Padding", JOptionPane.ERROR_MESSAGE);
                            return;
                        }
                        break;
                    case "CFB":
                        plainTextBytes = cipher.decryptCFB(cipherTextBytes, key);
                        break;
                    case "OFB":
                        plainTextBytes = cipher.decryptOFB(cipherTextBytes, key);
                        break;
                }
            }
            else {
                switch ((String) cipherMode.getSelectedItem()) {
                    case "ECB":
                        try {
                            plainTextBytes = enhancedInvCipher.decryptECB(cipherTextBytes, key);
                        } 
                        catch (InvalidDataException e) {
                            JOptionPane.showMessageDialog(this, "This ciphertext is either an invalid length or not padded correctly.", "Invalid Ciphertext", JOptionPane.ERROR_MESSAGE);
                            return;
                        }
                        break;
                    case "CBC":
                        try {
                            plainTextBytes = enhancedInvCipher.decryptCBC(cipherTextBytes, key);
                        } 
                        catch (InvalidDataException e) {
                            JOptionPane.showMessageDialog(this, "This ciphertext is either an invalid length or not padded correctly.", "Invalid Ciphertext", JOptionPane.ERROR_MESSAGE);
                            return;
                        }
                        break;
                    case "CFB":
                        plainTextBytes = enhancedCipher.decryptCFB(cipherTextBytes, key);
                        break;
                    case "OFB":
                        plainTextBytes = enhancedCipher.decryptOFB(cipherTextBytes, key);
                        break;
                }
            }
            String plainText = new String(plainTextBytes);
            plainTextArea.setText(plainText);
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
        byteEncodingLabel = new javax.swing.JLabel();
        byteEncoding = new javax.swing.JComboBox<>();
        encryptButton = new javax.swing.JRadioButton();
        decryptButton = new javax.swing.JRadioButton();
        runButton = new javax.swing.JButton();
        cipherMode = new javax.swing.JComboBox<>();
        modeLabel = new javax.swing.JLabel();
        aesButton = new javax.swing.JRadioButton();
        enhancedAESButton = new javax.swing.JRadioButton();

        keyArea.setColumns(20);
        keyArea.setRows(5);
        keyArea.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jScrollPane1.setViewportView(keyArea);

        keyLabel.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
        keyLabel.setText("Key (Hex or Base64)");

        plainTextArea.setColumns(20);
        plainTextArea.setRows(5);
        plainTextArea.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jScrollPane2.setViewportView(plainTextArea);

        plainTextLabel.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
        plainTextLabel.setText("Plaintext");

        cipherTextArea.setColumns(20);
        cipherTextArea.setRows(5);
        cipherTextArea.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jScrollPane3.setViewportView(cipherTextArea);

        cipherTextLabel.setText("Ciphertext (Hex or Base64)");

        byteEncodingLabel.setText("Key and Ciphertext Encoding:");

        byteEncoding.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Hex", "Base64" }));

        encryptButton.setSelected(true);
        encryptButton.setText("Encryption");

        decryptButton.setText("Decryption");

        runButton.setText("Run");
        runButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                runButtonActionPerformed(evt);
            }
        });

        cipherMode.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "ECB", "CBC", "CFB", "OFB" }));

        modeLabel.setText("Mode of Operation: ");

        aesButton.setSelected(true);
        aesButton.setText("AES");

        enhancedAESButton.setText("Enhanced AES");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addGap(291, 291, 291)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(keyLabel)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 414, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(28, 28, 28)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(byteEncodingLabel)
                                    .addComponent(byteEncoding, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(367, 367, 367)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(encryptButton)
                                    .addComponent(aesButton))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(enhancedAESButton)
                                    .addComponent(decryptButton)))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(429, 429, 429)
                                .addComponent(runButton)))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(modeLabel)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(cipherMode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 429, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(plainTextLabel))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 94, Short.MAX_VALUE)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 454, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(cipherTextLabel))))
                        .addGap(32, 32, 32))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(24, 24, 24)
                        .addComponent(keyLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 131, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(plainTextLabel)
                            .addComponent(cipherTextLabel)))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(61, 61, 61)
                        .addComponent(byteEncodingLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(byteEncoding, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 136, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 136, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(13, 13, 13)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(enhancedAESButton)
                            .addComponent(aesButton)))
                    .addGroup(layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(cipherMode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(modeLabel))))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(decryptButton)
                    .addComponent(encryptButton))
                .addGap(18, 18, 18)
                .addComponent(runButton)
                .addContainerGap(44, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void runButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_runButtonActionPerformed
        if (encryptButton.isSelected()) {
            encrypt();
        }
        else {
            decrypt();
        }
    }//GEN-LAST:event_runButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JRadioButton aesButton;
    private javax.swing.JComboBox<String> byteEncoding;
    private javax.swing.JLabel byteEncodingLabel;
    private javax.swing.JComboBox<String> cipherMode;
    private javax.swing.JTextArea cipherTextArea;
    private javax.swing.JLabel cipherTextLabel;
    private javax.swing.JRadioButton decryptButton;
    private javax.swing.JRadioButton encryptButton;
    private javax.swing.JRadioButton enhancedAESButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JTextArea keyArea;
    private javax.swing.JLabel keyLabel;
    private javax.swing.JLabel modeLabel;
    private javax.swing.JTextArea plainTextArea;
    private javax.swing.JLabel plainTextLabel;
    private javax.swing.JButton runButton;
    // End of variables declaration//GEN-END:variables
}
