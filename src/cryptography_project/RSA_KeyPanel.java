package cryptography_project;

import java.io.IOException;
import org.apache.commons.codec.binary.Base64;

/*
Author: Joshua Insel

RSA Key Generation Panel
Generates AES keys of user's choice of length
Uses ASN.1 encoding in Base64
*/

public class RSA_KeyPanel extends javax.swing.JPanel {
    private final RSA_KeyGenerator keyGen = new RSA_KeyGenerator();
    private RSA_PublicKey publicKey;
    private RSA_PrivateKey privateKey;

    public RSA_KeyPanel() {
        initComponents();
        publicKeyArea.setEditable(false);
        privateKeyArea.setEditable(false);
        setSize(1000, 500);
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        publicKeyArea = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        privateKeyArea = new javax.swing.JTextArea();
        publicKeyLabel = new javax.swing.JLabel();
        privateKeyLabel = new javax.swing.JLabel();
        keyLength = new javax.swing.JComboBox<>();
        keyLengthLabel = new javax.swing.JLabel();
        generateButton = new javax.swing.JButton();

        publicKeyArea.setColumns(20);
        publicKeyArea.setRows(5);
        jScrollPane1.setViewportView(publicKeyArea);

        privateKeyArea.setColumns(20);
        privateKeyArea.setRows(5);
        jScrollPane2.setViewportView(privateKeyArea);

        publicKeyLabel.setText("Public Key");

        privateKeyLabel.setText("Private Key");

        keyLength.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "1024", "2048", "4096" }));

        keyLengthLabel.setText("Key Length (in bits): ");

        generateButton.setText("Generate");
        generateButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                generateButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(384, 384, 384)
                        .addComponent(keyLengthLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(keyLength, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(427, 427, 427)
                        .addComponent(generateButton)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 439, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(publicKeyLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 39, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 442, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(privateKeyLabel))
                .addGap(20, 20, 20))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(publicKeyLabel)
                    .addComponent(privateKeyLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 157, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 157, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(keyLengthLabel)
                    .addComponent(keyLength, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(generateButton)
                .addContainerGap(346, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void generateButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_generateButtonActionPerformed
        keyGen.generateKeys(Integer.parseInt((String) keyLength.getSelectedItem()));
        publicKey = keyGen.getPublicKey();
        privateKey = keyGen.getPrivateKey();
        try {
            publicKeyArea.setText(Base64.encodeBase64String(publicKey.getEncoded()));
            privateKeyArea.setText(Base64.encodeBase64String(privateKey.getEncoded()));
        } 
        catch (IOException e) {}
    }//GEN-LAST:event_generateButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton generateButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JComboBox<String> keyLength;
    private javax.swing.JLabel keyLengthLabel;
    private javax.swing.JTextArea privateKeyArea;
    private javax.swing.JLabel privateKeyLabel;
    private javax.swing.JTextArea publicKeyArea;
    private javax.swing.JLabel publicKeyLabel;
    // End of variables declaration//GEN-END:variables
}
