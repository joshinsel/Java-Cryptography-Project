package cryptography_project;

import java.awt.CardLayout;

/*
Author: Joshua Insel

Menu for GUI
User can select AES, RSA, or SHA-2
*/

public class Menu extends javax.swing.JPanel {
    private CardLayout cl;

    public Menu() {
        initComponents();
        setSize(1000, 600);
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        title = new javax.swing.JLabel();
        aesButton = new javax.swing.JButton();
        rsaButton = new javax.swing.JButton();
        shaButton = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();

        setPreferredSize(new java.awt.Dimension(800, 600));

        title.setFont(new java.awt.Font("Arial", 0, 36)); // NOI18N
        title.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        title.setText("Cryptography Project");

        aesButton.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        aesButton.setText("AES");
        aesButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                aesButtonActionPerformed(evt);
            }
        });

        rsaButton.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        rsaButton.setText("RSA");
        rsaButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rsaButtonActionPerformed(evt);
            }
        });

        shaButton.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        shaButton.setText("SHA-2");
        shaButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                shaButtonActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel1.setText("Written by: Joshua Insel");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(81, 81, 81)
                .addComponent(aesButton, javax.swing.GroupLayout.PREFERRED_SIZE, 142, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(187, 187, 187)
                .addComponent(rsaButton, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 200, Short.MAX_VALUE)
                .addComponent(shaButton, javax.swing.GroupLayout.PREFERRED_SIZE, 142, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(102, 102, 102))
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(286, 286, 286)
                        .addComponent(title, javax.swing.GroupLayout.PREFERRED_SIZE, 384, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(380, 380, 380)
                        .addComponent(jLabel1)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(title)
                .addGap(158, 158, 158)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(shaButton, javax.swing.GroupLayout.PREFERRED_SIZE, 71, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(rsaButton, javax.swing.GroupLayout.PREFERRED_SIZE, 71, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(aesButton, javax.swing.GroupLayout.PREFERRED_SIZE, 71, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(127, 127, 127)
                .addComponent(jLabel1)
                .addContainerGap(166, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents
    
    private void rsaButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rsaButtonActionPerformed
        cl = (CardLayout) getParent().getLayout();
        cl.show(getParent(), "RSA");
    }//GEN-LAST:event_rsaButtonActionPerformed

    private void aesButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_aesButtonActionPerformed
        cl = (CardLayout) getParent().getLayout();
        cl.show(getParent(), "AES");
    }//GEN-LAST:event_aesButtonActionPerformed

    private void shaButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_shaButtonActionPerformed
        cl = (CardLayout) getParent().getLayout();
        cl.show(getParent(), "SHA-2");
    }//GEN-LAST:event_shaButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton aesButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JButton rsaButton;
    private javax.swing.JButton shaButton;
    private javax.swing.JLabel title;
    // End of variables declaration//GEN-END:variables
}
