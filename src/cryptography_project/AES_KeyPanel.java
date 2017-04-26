package cryptography_project;

import org.apache.commons.codec.binary.*;

/*
Author: Joshua Insel

AES Key Generation Panel
Generates AES keys of user's choice of length
Key encoding can be hex or Base64
*/

public class AES_KeyPanel extends javax.swing.JPanel {
    private final AES_Key key = new AES_Key();
    
    public AES_KeyPanel() {
        initComponents();
        keyArea.setEditable(false);
        setSize(1000, 500);
    }
    
    private void generateKey() {
        switch ((String) keyLength.getSelectedItem()) {
            case "128":
                key.generateKey(128);
                break;
            case "192":
                key.generateKey(192);
                break;
            case "256":
                key.generateKey(256);
                break;
        }
        byte[] keyBytes = key.getKey();
        String keyText;
        if (((String) encoding.getSelectedItem()).equals("Hex")) {
            keyText = Hex.encodeHexString(keyBytes);
            keyArea.setText(keyText);
        }
        else {
            keyText = Base64.encodeBase64String(keyBytes);
            keyArea.setText(keyText);
        }
    }
    
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        encoding = new javax.swing.JComboBox<>();
        encodingLabel = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        keyLength = new javax.swing.JComboBox<>();
        keyLengthLabel = new javax.swing.JLabel();
        generateButton = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        keyArea = new javax.swing.JTextArea();

        encoding.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Hex", "Base64" }));

        encodingLabel.setText("Encoding:");

        jLabel1.setText("Key");

        keyLength.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "128", "192", "256" }));

        keyLengthLabel.setText("Key Length (in bits):");

        generateButton.setText("Generate");
        generateButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                generateButtonActionPerformed(evt);
            }
        });

        keyArea.setColumns(20);
        keyArea.setRows(5);
        jScrollPane1.setViewportView(keyArea);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(273, 273, 273)
                        .addComponent(encodingLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 57, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(encoding, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(118, 118, 118)
                        .addComponent(keyLengthLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(keyLength, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(424, 424, 424)
                        .addComponent(generateButton))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(273, 273, 273)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 417, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(310, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap(94, Short.MAX_VALUE)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 152, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(27, 27, 27)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(encoding, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(keyLength, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(keyLengthLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(encodingLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 21, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(14, 14, 14)
                .addComponent(generateButton)
                .addGap(147, 147, 147))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void generateButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_generateButtonActionPerformed
        generateKey();
    }//GEN-LAST:event_generateButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox<String> encoding;
    private javax.swing.JLabel encodingLabel;
    private javax.swing.JButton generateButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea keyArea;
    private javax.swing.JComboBox<String> keyLength;
    private javax.swing.JLabel keyLengthLabel;
    // End of variables declaration//GEN-END:variables
}
