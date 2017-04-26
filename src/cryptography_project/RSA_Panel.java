package cryptography_project;

import java.awt.CardLayout;

/*
Author: Joshua Insel

Panel for RSA Operations
Uses TabbedPane for switching between RSA Panels
*/

public class RSA_Panel extends javax.swing.JPanel {
    private CardLayout cl;

    public RSA_Panel() {
        initComponents();
        tabs.add("Key Generation", new RSA_KeyPanel());
        tabs.add("RSA Encryption", new RSA_EncryptionPanel());
        tabs.add("RSA Decryption", new RSA_DecryptionPanel());
        tabs.add("RSA-OAEP Encryption", new RSA_OAEP_EncryptionPanel());
        tabs.add("RSA-OAEP Decryption", new RSA_OAEP_DecryptionPanel());
    }
    
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        tabs = new javax.swing.JTabbedPane();
        menuButton = new javax.swing.JButton();

        menuButton.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        menuButton.setText("Main Menu");
        menuButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                menuButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(tabs)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(menuButton)
                .addContainerGap(869, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(tabs, javax.swing.GroupLayout.PREFERRED_SIZE, 511, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(menuButton)
                .addGap(0, 25, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void menuButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_menuButtonActionPerformed
        cl = (CardLayout) getParent().getLayout();
        cl.show(getParent(), "Menu");
    }//GEN-LAST:event_menuButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton menuButton;
    private javax.swing.JTabbedPane tabs;
    // End of variables declaration//GEN-END:variables
}
