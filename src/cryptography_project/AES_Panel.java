package cryptography_project;

import java.awt.CardLayout;

/*
Author: Joshua Insel

Panel for AES Operations
Uses TabbedPane for switching between AES Panels
*/

public class AES_Panel extends javax.swing.JPanel {
    private CardLayout cl;
    
    public AES_Panel() {
        initComponents();
        tabs.add(new AES_KeyPanel(), "Key Generation");
        tabs.add(new AES_Text(), "Text Encryption/Decryption");
        tabs.add(new AES_EncryptionFilePanel(), "File Encryption");
        tabs.add(new AES_DecryptionFilePanel(), "File Decryption");
        setSize(1000, 600);
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        menuButton = new javax.swing.JButton();
        tabs = new javax.swing.JTabbedPane();

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
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(menuButton)
                .addContainerGap(869, Short.MAX_VALUE))
            .addComponent(tabs)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(tabs, javax.swing.GroupLayout.PREFERRED_SIZE, 507, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(menuButton)
                .addContainerGap())
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
