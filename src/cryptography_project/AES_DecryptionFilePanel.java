package cryptography_project;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import javax.swing.ButtonGroup;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.*;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

/*
Author: Joshua Insel

AES File Decryption Panel
Decrypts user-inputted .txt file with ciphertext and saves plaintext to user-inputted file
Choice of Hex or Base64 encoding for keys and ciphertext (key and ciphertext must match the input)
*/

public class AES_DecryptionFilePanel extends javax.swing.JPanel {
    private final AES_Cipher cipher = new AES_Cipher();
    private final AES_InvCipher invCipher = new AES_InvCipher();
    private final AES_EnhancedCipher enhancedCipher = new AES_EnhancedCipher();
    private final AES_EnhancedInvCipher enhancedInvCipher = new AES_EnhancedInvCipher();
    private final AES_Key key = new AES_Key();
    private final ButtonGroup aesButtons = new ButtonGroup();
    private File plainTextFile;
    private File cipherTextFile;
    private final JFileChooser fc = new JFileChooser();

    public AES_DecryptionFilePanel() {
        initComponents();
        aesButtons.add(aesButton);
        aesButtons.add(enhancedAESButton);
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
    
    private void decrypt() {
        try {
            decodeKey();
            String cipherText = null;
            try {
                try {
                    BufferedReader reader = new BufferedReader(new FileReader(cipherTextFile));
                    cipherText = reader.readLine();
                    reader.close();
                } 
                catch (FileNotFoundException ex) {}
            }
            catch (IOException e) {}
            if (cipherText.trim().equals("")) {
                JOptionPane.showMessageDialog(this, "The ciphertext file is blank.", "Invalid Ciphertext", JOptionPane.ERROR_MESSAGE);
                return;
            }
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
            try {
                FileUtils.writeByteArrayToFile(plainTextFile, plainTextBytes);
            }
            catch (IOException e) {}
        } 
        catch (InvalidKeyException ex) {}
    }
    
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        keyArea = new javax.swing.JTextArea();
        jLabel1 = new javax.swing.JLabel();
        encodingLabel = new javax.swing.JLabel();
        byteEncoding = new javax.swing.JComboBox<>();
        filePath1Label = new javax.swing.JLabel();
        cipherTextFilePath = new javax.swing.JTextField();
        cipherTextBrowseButton = new javax.swing.JButton();
        filePath2Label = new javax.swing.JLabel();
        plainTextFilePath = new javax.swing.JTextField();
        plainTextBrowseButton = new javax.swing.JButton();
        cipherMode = new javax.swing.JComboBox<>();
        jLabel3 = new javax.swing.JLabel();
        aesButton = new javax.swing.JRadioButton();
        enhancedAESButton = new javax.swing.JRadioButton();
        decryptButton = new javax.swing.JButton();

        keyArea.setColumns(20);
        keyArea.setRows(5);
        jScrollPane1.setViewportView(keyArea);

        jLabel1.setText("Key");

        encodingLabel.setText("Hex and Ciphertext Encoding:");

        byteEncoding.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Hex", "Base64" }));

        filePath1Label.setText("Ciphertext Filepath (.txt only)");

        cipherTextBrowseButton.setText("Browse");
        cipherTextBrowseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cipherTextBrowseButtonActionPerformed(evt);
            }
        });

        filePath2Label.setText("Plaintext Filepath");

        plainTextBrowseButton.setText("Browse");
        plainTextBrowseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                plainTextBrowseButtonActionPerformed(evt);
            }
        });

        cipherMode.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "ECB", "CBC", "CFB", "OFB" }));

        jLabel3.setText("Mode of Operation:");

        aesButton.setText("AES");

        enhancedAESButton.setText("Enhanced AES");

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
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 484, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(byteEncoding, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(encodingLabel, javax.swing.GroupLayout.Alignment.TRAILING))))
                        .addGap(63, 63, 63))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(cipherMode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(aesButton)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(filePath1Label)
                                .addGroup(layout.createSequentialGroup()
                                    .addComponent(cipherTextFilePath, javax.swing.GroupLayout.PREFERRED_SIZE, 384, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(cipherTextBrowseButton))
                                .addComponent(jLabel3)))
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 90, Short.MAX_VALUE)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(filePath2Label)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(plainTextFilePath, javax.swing.GroupLayout.PREFERRED_SIZE, 329, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(plainTextBrowseButton)))
                                .addGap(21, 21, 21))
                            .addGroup(layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(enhancedAESButton)
                                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(decryptButton)
                .addGap(456, 456, 456))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(96, 96, 96)
                        .addComponent(encodingLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(byteEncoding, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(21, 21, 21)
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 143, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 51, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(filePath2Label)
                    .addComponent(filePath1Label))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(plainTextFilePath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(cipherTextFilePath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(cipherTextBrowseButton)
                    .addComponent(plainTextBrowseButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cipherMode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(aesButton)
                    .addComponent(enhancedAESButton))
                .addGap(18, 18, 18)
                .addComponent(decryptButton)
                .addGap(91, 91, 91))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void cipherTextBrowseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cipherTextBrowseButtonActionPerformed
        int returnVal = fc.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            cipherTextFile = fc.getSelectedFile();
            if (!FilenameUtils.getExtension(cipherTextFile.getName()).equals("txt")) {
                JOptionPane.showMessageDialog(this, "This must be a .txt file.", "Invalid File Name", JOptionPane.ERROR_MESSAGE);
                cipherTextFile = null;
            }
            else {
                cipherTextFilePath.setText(cipherTextFile.getPath());
            }
        }
    }//GEN-LAST:event_cipherTextBrowseButtonActionPerformed

    private void plainTextBrowseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_plainTextBrowseButtonActionPerformed
        int returnVal = fc.showSaveDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            plainTextFile = fc.getSelectedFile();
            plainTextFilePath.setText(plainTextFile.getPath());
        }
    }//GEN-LAST:event_plainTextBrowseButtonActionPerformed

    private void decryptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decryptButtonActionPerformed
        decrypt();
    }//GEN-LAST:event_decryptButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JRadioButton aesButton;
    private javax.swing.JComboBox<String> byteEncoding;
    private javax.swing.JComboBox<String> cipherMode;
    private javax.swing.JButton cipherTextBrowseButton;
    private javax.swing.JTextField cipherTextFilePath;
    private javax.swing.JButton decryptButton;
    private javax.swing.JLabel encodingLabel;
    private javax.swing.JRadioButton enhancedAESButton;
    private javax.swing.JLabel filePath1Label;
    private javax.swing.JLabel filePath2Label;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea keyArea;
    private javax.swing.JButton plainTextBrowseButton;
    private javax.swing.JTextField plainTextFilePath;
    // End of variables declaration//GEN-END:variables
}
