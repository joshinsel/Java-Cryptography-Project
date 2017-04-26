package cryptography_project;

import java.awt.CardLayout;
import javax.swing.JPanel;

/*
Author: Joshua Insel

Frame for GUI
*/

public class GUI_Main extends javax.swing.JFrame {
    //Switches between menu and different algorithms using CardLayout
    JPanel cards; 
    CardLayout cl; 

    public GUI_Main() {
        initComponents();
        setTitle("Cryptography Project");
        setSize(1000, 600);
        cl = new CardLayout();
        cards = new JPanel(cl);
        cards.add(new Menu(), "Menu");
        cards.add(new AES_Panel(), "AES");
        cards.add(new RSA_Panel(), "RSA");
        cards.add(new SHA2_Panel(), "SHA-2");
        cards.setSize(1000, 600);
        add(cards);
        setVisible(true);
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 1000, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 600, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    // End of variables declaration//GEN-END:variables
}
