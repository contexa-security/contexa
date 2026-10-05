package io.contexa.showcase.business.work;

/** A business key that does not exist in the virtual company; the API answers 404. */
public class BusinessNotFoundException extends RuntimeException {

    public BusinessNotFoundException(String kind, String key) {
        super(kind + " not found: " + key);
    }
}
