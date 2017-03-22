/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptography_project;

/**
 *
 * @author joshi
 */
public class InvalidDataException extends IllegalArgumentException {
    public InvalidDataException(){super();}
    public InvalidDataException(String message) {super(message);}
}
