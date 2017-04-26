package cryptography_project;

/*
Author: Joshua Insel

Exception for invalid input data in algorithms
*/

public class InvalidDataException extends IllegalArgumentException {
    public InvalidDataException(){super();}
    public InvalidDataException(String message) {super(message);}
}
