package cryptography_project;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import javax.swing.ButtonGroup;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.*;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

/*
Author: Joshua Insel

AES File Encryption Panel
Encrypts user-inputted file and saves ciphertext to user-inputted .txt file
Choice of Hex or Base64 encoding for keys and ciphertext (key must match the input)
*/

public class AES_EncryptionFilePanel extends javax.swing.JPanel {
    private final AES_Cipher cipher = new AES_Cipher();
    private final AES_EnhancedCipher enhancedCipher = new AES_EnhancedCipher();
    private final AES_Key key = new AES_Key();
    private final ButtonGroup aesButtons = new ButtonGroup();
    private File plainTextFile;
    private File cipherTextFile;
    private final JFileChooser fc = new JFileChooser();
    
    public AES_EncryptionFilePanel() {
        initComponents();
        aesButtons.add(aesButton);
        aesButtons.add(enhancedAESButton);
        plainTextFilePath.setEditable(false);
        cipherTextFilePath.setEditable(false);
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
            if (plainTextFile == null || cipherTextFile == null) {
                if (plainTextFile == null) {
                    JOptionPane.showMessageDialog(this, "There is no file selected for the plaintext.", "No Plaintext File Selected", JOptionPane.ERROR_MESSAGE);
                }
                if (cipherTextFile == null) {
                    JOptionPane.showMessageDialog(this, "There is no file selected for the ciphertext.", "No Ciphertext File Selected", JOptionPane.ERROR_MESSAGE);
                }
                return;
            }
            byte[] plainTextBytes = null;
            try {
                plainTextBytes = IOUtils.toByteArray(new FileInputStream(plainTextFile));
            } 
            catch (IOException ex) {}
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
            } 
            else {
                cipherText = Base64.encodeBase64String(cipherTextBytes);
            }
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(cipherTextFile))) {
                writer.write(cipherText);
                writer.close();
            }
            catch (IOException e) {}
        }
        catch (InvalidKeyException e) {}
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        keyArea = new javax.swing.JTextArea();
        keyLabel = new javax.swing.JLabel();
        plainTextFilePath = new javax.swing.JTextField();
        filePath1Label = new javax.swing.JLabel();
        cipherTextFilePath = new javax.swing.JTextField();
        filePath2Label = new javax.swing.JLabel();
        plainTextBrowseButton = new javax.swing.JButton();
        cipherTextBrowseButton = new javax.swing.JButton();
        cipherMode = new javax.swing.JComboBox<>();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        byteEncoding = new javax.swing.JComboBox<>();
        aesButton = new javax.swing.JRadioButton();
        enhancedAESButton = new javax.swing.JRadioButton();
        encryptButton = new javax.swing.JButton();

        keyArea.setColumns(20);
        keyArea.setRows(5);
        jScrollPane1.setViewportView(keyArea);

        keyLabel.setText("Key");

        filePath1Label.setText("Plaintext Filepath");

        filePath2Label.setText("Ciphertext Filepath (.txt only)");

        plainTextBrowseButton.setText("Browse");
        plainTextBrowseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                plainTextBrowseButtonActionPerformed(evt);
            }
        });

        cipherTextBrowseButton.setText("Browse");
        cipherTextBrowseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cipherTextBrowseButtonActionPerformed(evt);
            }
        });

        cipherMode.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "ECB", "CBC", "CFB", "OFB" }));

        jLabel1.setText("Hex and Ciphertext Encoding:");

        jLabel2.setText("Mode of Operation: ");

        byteEncoding.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Hex", "Base64" }));

        aesButton.setSelected(true);
        aesButton.setText("AES ");

        enhancedAESButton.setText("Enhanced AES");

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
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(265, 265, 265)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(keyLabel)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 480, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(27, 27, 27)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(jLabel1)
                                    .addComponent(byteEncoding, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(filePath1Label))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(plainTextFilePath, javax.swing.GroupLayout.PREFERRED_SIZE, 369, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(plainTextBrowseButton)
                                .addGap(90, 90, 90)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(cipherTextFilePath, javax.swing.GroupLayout.PREFERRED_SIZE, 315, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(cipherTextBrowseButton))
                                    .addComponent(filePath2Label)))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(14, 14, 14)
                                .addComponent(aesButton)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGap(18, 18, Short.MAX_VALUE)
                                        .addComponent(jLabel2)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(cipherMode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(83, 83, 83))
                                    .addGroup(layout.createSequentialGroup()
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(enhancedAESButton)
                                        .addGap(0, 0, Short.MAX_VALUE)))))))
                .addContainerGap(50, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addGap(446, 446, 446)
                .addComponent(encryptButton)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addComponent(keyLabel)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 143, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(56, 56, 56)
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(byteEncoding, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 40, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(filePath1Label)
                    .addComponent(filePath2Label))
                .addGap(9, 9, 9)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(plainTextFilePath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(plainTextBrowseButton))
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(cipherTextFilePath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(cipherTextBrowseButton)))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(cipherMode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(enhancedAESButton, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(aesButton))
                .addGap(18, 18, 18)
                .addComponent(encryptButton)
                .addGap(113, 113, 113))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void plainTextBrowseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_plainTextBrowseButtonActionPerformed
        int returnVal = fc.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            plainTextFile = fc.getSelectedFile();
            if (plainTextFile.length() > Integer.MAX_VALUE) {
                JOptionPane.showMessageDialog(this, "The input file cannot be larger than "
                        + (double) Integer.MAX_VALUE / 1000000000 + " GB.", "Too Large File", JOptionPane.ERROR_MESSAGE);
                plainTextFile = null;
            } 
            else {
                plainTextFilePath.setText(plainTextFile.getPath());
            }
        }
    }//GEN-LAST:event_plainTextBrowseButtonActionPerformed

    private void cipherTextBrowseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cipherTextBrowseButtonActionPerformed
        int returnVal = fc.showSaveDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            cipherTextFile = fc.getSelectedFile();
            if (!FilenameUtils.getExtension(cipherTextFile.getName()).equals("txt")) {
                JOptionPane.showMessageDialog(this, "This must be saved to a .txt file.", "Invalid File Name", JOptionPane.ERROR_MESSAGE);
                cipherTextFile = null;
            }
            else {
                cipherTextFilePath.setText(cipherTextFile.getPath());
            }
        }
    }//GEN-LAST:event_cipherTextBrowseButtonActionPerformed

    private void encryptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encryptButtonActionPerformed
        encrypt();
    }//GEN-LAST:event_encryptButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JRadioButton aesButton;
    private javax.swing.JComboBox<String> byteEncoding;
    private javax.swing.JComboBox<String> cipherMode;
    private javax.swing.JButton cipherTextBrowseButton;
    private javax.swing.JTextField cipherTextFilePath;
    private javax.swing.JButton encryptButton;
    private javax.swing.JRadioButton enhancedAESButton;
    private javax.swing.JLabel filePath1Label;
    private javax.swing.JLabel filePath2Label;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea keyArea;
    private javax.swing.JLabel keyLabel;
    private javax.swing.JButton plainTextBrowseButton;
    private javax.swing.JTextField plainTextFilePath;
    // End of variables declaration//GEN-END:variables
}
