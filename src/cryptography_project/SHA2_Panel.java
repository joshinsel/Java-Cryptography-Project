package cryptography_project;

import java.awt.CardLayout;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import javax.swing.ButtonGroup;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.*;
import org.apache.commons.io.IOUtils;

/*
Author: Joshua Insel

SHA-2 Panel
Gets SHA-256 or SHA-512 message digest from user-inputted text or file
Performs checksum operation on user-inputted text or file with existing message digest
*/

public class SHA2_Panel extends javax.swing.JPanel {
    private final ButtonGroup inputButtons = new ButtonGroup();
    private final ButtonGroup algorithmButtons = new ButtonGroup();
    private CardLayout cl;
    private File inputFile;
    private final SHA_256 sha256 = new SHA_256();
    private final SHA_512 sha512 = new SHA_512();
    
    
    public SHA2_Panel() {
        initComponents();
        filePath.setEditable(false);
        inputButtons.add(textButton);
        inputButtons.add(fileButton);
        algorithmButtons.add(sha256Button);
        algorithmButtons.add(sha512Button);
        setSize(1000, 600);
    }

    private byte[] getDigest() throws IOException {
        byte[] input = null;
        if (textButton.isSelected()) {
            String inputText = textArea.getText();
            input = inputText.getBytes();
        }
        else {
            if (inputFile != null) {
                try { 
                    input = IOUtils.toByteArray(new FileInputStream(inputFile));
                } 
                catch (IOException ex) {}
            }
            else {
                JOptionPane.showMessageDialog(this, "There is no file selected.", "No File Selected", JOptionPane.ERROR_MESSAGE);
                throw new IOException();
            }
        }
        byte[] digest;
        if (sha256Button.isSelected()) {
            digest = sha256.digest(input);
        }
        else {
            digest = sha512.digest(input);
        }
        return digest;
    }
    
    private void checksum() {
        try {
            byte[] inputDigest = getDigest();
            byte[] checksumDigest;
            if (((String) digestEncoding.getSelectedItem()).equals("Hex")) {
                try {
                    checksumDigest = Hex.decodeHex(digestArea.getText().trim().toCharArray());
                    System.out.println(checksumDigest.length);
                    if (sha256Button.isSelected() && checksumDigest.length != 32) {
                         JOptionPane.showMessageDialog(this, "A SHA-256 digest must be 256 bits.", "Invalid SHA-256 Digest", JOptionPane.ERROR_MESSAGE);
                    }
                    else if (sha512Button.isSelected() && checksumDigest.length != 64) {
                         JOptionPane.showMessageDialog(this, "A SHA-512 digest be 512 bits.", "Invalid SHA-512 Digest", JOptionPane.ERROR_MESSAGE);
                    }
                    else {
                        if (Arrays.equals(inputDigest, checksumDigest)) {
                            JOptionPane.showMessageDialog(this, "This digest matches the input.", "Match!", JOptionPane.INFORMATION_MESSAGE);
                        } 
                        else {
                            JOptionPane.showMessageDialog(this, "This digest does not match the input.", "No Match", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
                catch (DecoderException e) {
                    JOptionPane.showMessageDialog(this, "Not a valid hex string for digest.", "Invalid Digest Hex String", JOptionPane.ERROR_MESSAGE);
                }
            } 
            else {
                checksumDigest = Base64.decodeBase64(digestArea.getText().trim());
                if (sha256Button.isSelected() && checksumDigest.length != 32) {
                    JOptionPane.showMessageDialog(this, "A SHA-256 digest must be 256 bits.", "Invalid SHA-256 Digest", JOptionPane.ERROR_MESSAGE);
                }
                else if (sha512Button.isSelected() && checksumDigest.length != 64) {
                    JOptionPane.showMessageDialog(this, "A SHA-512 digest be 512 bits.", "Invalid SHA-512 Digest", JOptionPane.ERROR_MESSAGE);
                }
                else {
                    if (Arrays.equals(inputDigest, checksumDigest)) {
                        JOptionPane.showMessageDialog(this, "This digest matches the input.", "Match!", JOptionPane.INFORMATION_MESSAGE);
                    } 
                    else {
                        JOptionPane.showMessageDialog(this, "This digest does not match the input.", "No Match", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        }
        catch (IOException e) {}
    }
    
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        menuButton = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        textArea = new javax.swing.JTextArea();
        textLabel = new javax.swing.JLabel();
        filePath = new javax.swing.JTextField();
        browseButton = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        digestArea = new javax.swing.JTextArea();
        digestLabel = new javax.swing.JLabel();
        textButton = new javax.swing.JRadioButton();
        fileButton = new javax.swing.JRadioButton();
        algorithmLabel = new javax.swing.JLabel();
        sha256Button = new javax.swing.JRadioButton();
        sha512Button = new javax.swing.JRadioButton();
        digestButton = new javax.swing.JButton();
        checksumButton = new javax.swing.JButton();
        encodingLabel = new javax.swing.JLabel();
        digestEncoding = new javax.swing.JComboBox<>();
        fileLabel = new javax.swing.JLabel();
        inputLabel = new javax.swing.JLabel();

        menuButton.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        menuButton.setText("Main Menu");
        menuButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                menuButtonActionPerformed(evt);
            }
        });

        textArea.setColumns(20);
        textArea.setRows(5);
        jScrollPane1.setViewportView(textArea);

        textLabel.setText("Text");

        browseButton.setText("Browse");
        browseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                browseButtonActionPerformed(evt);
            }
        });

        digestArea.setColumns(20);
        digestArea.setRows(5);
        jScrollPane2.setViewportView(digestArea);

        digestLabel.setText("Digest");

        textButton.setSelected(true);
        textButton.setText("Text");

        fileButton.setText("File");

        algorithmLabel.setText("Algorithm");

        sha256Button.setSelected(true);
        sha256Button.setText("SHA-256");

        sha512Button.setText("SHA-512");

        digestButton.setText("Get Digest");
        digestButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                digestButtonActionPerformed(evt);
            }
        });

        checksumButton.setText("Checksum");
        checksumButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                checksumButtonActionPerformed(evt);
            }
        });

        encodingLabel.setText("Digest Encoding: ");

        digestEncoding.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Hex", "Base64" }));

        fileLabel.setText("File Path");

        inputLabel.setText("Input");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(menuButton)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(393, 393, 393)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(sha256Button)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(sha512Button))
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(digestButton)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(checksumButton)))))
                        .addContainerGap(406, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(5, 5, 5)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 448, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(textLabel)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGap(7, 7, 7)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(inputLabel)
                                            .addGroup(layout.createSequentialGroup()
                                                .addComponent(textButton)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(fileButton)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(algorithmLabel)))))
                                .addGroup(layout.createSequentialGroup()
                                    .addComponent(filePath, javax.swing.GroupLayout.PREFERRED_SIZE, 366, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(browseButton)))
                            .addComponent(fileLabel))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(encodingLabel)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(digestEncoding, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(digestLabel)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 430, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(31, 31, 31))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(textLabel)
                    .addComponent(digestLabel))
                .addGap(7, 7, 7)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 200, Short.MAX_VALUE)
                            .addComponent(jScrollPane2))
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(12, 12, 12)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(encodingLabel)
                                    .addComponent(digestEncoding, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(10, 10, 10)
                                .addComponent(fileLabel)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(filePath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))))
                    .addComponent(browseButton))
                .addGap(45, 45, 45)
                .addComponent(inputLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(algorithmLabel)
                    .addComponent(fileButton)
                    .addComponent(textButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(sha256Button)
                    .addComponent(sha512Button))
                .addGap(43, 43, 43)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(digestButton)
                    .addComponent(checksumButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 32, Short.MAX_VALUE)
                .addComponent(menuButton)
                .addGap(59, 59, 59))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void menuButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_menuButtonActionPerformed
        cl = (CardLayout) getParent().getLayout();
        cl.show(getParent(), "Menu");
    }//GEN-LAST:event_menuButtonActionPerformed

    private void browseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_browseButtonActionPerformed
        JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            inputFile = fc.getSelectedFile();
            if (inputFile.length() > Integer.MAX_VALUE) {
                JOptionPane.showMessageDialog(this, "The input file cannot be larger than "
                        + (double) Integer.MAX_VALUE / 1000000000 + " GB.", "Too Large File", JOptionPane.ERROR_MESSAGE);
                inputFile = null;
            } 
            else {
                filePath.setText(inputFile.getPath());
            }
        }
    }//GEN-LAST:event_browseButtonActionPerformed

    private void digestButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_digestButtonActionPerformed
        try {
            byte[] digest = getDigest();
            String digestText;
            if (((String) digestEncoding.getSelectedItem()).equals("Hex")) {
                digestText = Hex.encodeHexString(digest);
                digestArea.setText(digestText);
            } 
            else {
                digestText = Base64.encodeBase64String(digest);
                digestArea.setText(digestText);
            }
        }
        catch (IOException e) {}
    }//GEN-LAST:event_digestButtonActionPerformed

    private void checksumButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_checksumButtonActionPerformed
        checksum();
    }//GEN-LAST:event_checksumButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel algorithmLabel;
    private javax.swing.JButton browseButton;
    private javax.swing.JButton checksumButton;
    private javax.swing.JTextArea digestArea;
    private javax.swing.JButton digestButton;
    private javax.swing.JComboBox<String> digestEncoding;
    private javax.swing.JLabel digestLabel;
    private javax.swing.JLabel encodingLabel;
    private javax.swing.JRadioButton fileButton;
    private javax.swing.JLabel fileLabel;
    private javax.swing.JTextField filePath;
    private javax.swing.JLabel inputLabel;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JButton menuButton;
    private javax.swing.JRadioButton sha256Button;
    private javax.swing.JRadioButton sha512Button;
    private javax.swing.JTextArea textArea;
    private javax.swing.JRadioButton textButton;
    private javax.swing.JLabel textLabel;
    // End of variables declaration//GEN-END:variables
}
