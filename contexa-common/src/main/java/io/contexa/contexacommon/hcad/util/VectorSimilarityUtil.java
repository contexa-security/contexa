package io.contexa.contexacommon.hcad.util;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class VectorSimilarityUtil {

    
    private static volatile Boolean nd4jAvailable = null;

    
    public static double cosineSimilarity(double[] vecA, double[] vecB) {
        if (vecA == null || vecB == null) {
            log.warn("[VectorSimilarityUtil] Null vector provided");
            return Double.NaN;  
        }

        if (vecA.length != vecB.length) {
            log.warn("[VectorSimilarityUtil] Vector dimension mismatch: {} vs {}", vecA.length, vecB.length);
            return Double.NaN;  
        }

        if (vecA.length == 0) {
            log.warn("[VectorSimilarityUtil] Empty vector provided");
            return Double.NaN;  
        }

        try {
            if (isND4JAvailable()) {
                return cosineSimilarityWithND4J(vecA, vecB);
            }
        } catch (Throwable e) {
            log.debug("[VectorSimilarityUtil] ND4J failed, falling back to pure Java: {}", e.getMessage());
        }

        return cosineSimilarityPureJava(vecA, vecB);
    }

    
    public static double cosineSimilarity(float[] vecA, float[] vecB) {
        if (vecA == null || vecB == null) {
            log.warn("[VectorSimilarityUtil] Null vector provided");
            return Double.NaN;  
        }

        if (vecA.length != vecB.length) {
            log.warn("[VectorSimilarityUtil] Vector dimension mismatch: {} vs {}", vecA.length, vecB.length);
            return Double.NaN;  
        }

        if (vecA.length == 0) {
            log.warn("[VectorSimilarityUtil] Empty vector provided");
            return Double.NaN;  
        }

        try {
            if (isND4JAvailable()) {
                return cosineSimilarityWithND4J(vecA, vecB);
            }
        } catch (Throwable e) {
            log.debug("[VectorSimilarityUtil] ND4J failed, falling back to pure Java: {}", e.getMessage());
        }

        return cosineSimilarityPureJava(vecA, vecB);
    }

    

    
    private static double cosineSimilarityWithND4J(double[] vecA, double[] vecB) {
        org.nd4j.linalg.api.ndarray.INDArray ndA = org.nd4j.linalg.factory.Nd4j.create(vecA);
        org.nd4j.linalg.api.ndarray.INDArray ndB = org.nd4j.linalg.factory.Nd4j.create(vecB);
        double similarity = org.nd4j.linalg.ops.transforms.Transforms.cosineSim(ndA, ndB);

        
        if (Double.isNaN(similarity) || Double.isInfinite(similarity)) {
            log.warn("[VectorSimilarityUtil] ND4J returned invalid value: {}", similarity);
            return Double.NaN;
        }

        
        return (similarity + 1.0) / 2.0;
    }

    
    private static double cosineSimilarityWithND4J(float[] vecA, float[] vecB) {
        org.nd4j.linalg.api.ndarray.INDArray ndA = org.nd4j.linalg.factory.Nd4j.create(vecA);
        org.nd4j.linalg.api.ndarray.INDArray ndB = org.nd4j.linalg.factory.Nd4j.create(vecB);
        double similarity = org.nd4j.linalg.ops.transforms.Transforms.cosineSim(ndA, ndB);

        
        if (Double.isNaN(similarity) || Double.isInfinite(similarity)) {
            log.warn("[VectorSimilarityUtil] ND4J returned invalid value: {}", similarity);
            return Double.NaN;
        }

        
        return (similarity + 1.0) / 2.0;
    }

    

    
    private static double cosineSimilarityPureJava(double[] vecA, double[] vecB) {
        double dotProduct = 0.0;
        double normA = 0.0;
        double normB = 0.0;

        
        int i = 0;
        int len = vecA.length;
        int limit = len - 3;

        for (; i < limit; i += 4) {
            
            double a0 = vecA[i], a1 = vecA[i + 1], a2 = vecA[i + 2], a3 = vecA[i + 3];
            double b0 = vecB[i], b1 = vecB[i + 1], b2 = vecB[i + 2], b3 = vecB[i + 3];

            dotProduct += a0 * b0 + a1 * b1 + a2 * b2 + a3 * b3;
            normA += a0 * a0 + a1 * a1 + a2 * a2 + a3 * a3;
            normB += b0 * b0 + b1 * b1 + b2 * b2 + b3 * b3;
        }

        
        for (; i < len; i++) {
            dotProduct += vecA[i] * vecB[i];
            normA += vecA[i] * vecA[i];
            normB += vecB[i] * vecB[i];
        }

        
        if (normA == 0.0 || normB == 0.0) {
            return Double.NaN;
        }

        double similarity = dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
        
        
        return (similarity + 1.0) / 2.0;
    }

    
    private static double cosineSimilarityPureJava(float[] vecA, float[] vecB) {
        double dotProduct = 0.0;
        double normA = 0.0;
        double normB = 0.0;

        
        int i = 0;
        int len = vecA.length;
        int limit = len - 3;

        for (; i < limit; i += 4) {
            
            float a0 = vecA[i], a1 = vecA[i + 1], a2 = vecA[i + 2], a3 = vecA[i + 3];
            float b0 = vecB[i], b1 = vecB[i + 1], b2 = vecB[i + 2], b3 = vecB[i + 3];

            dotProduct += (double)a0 * b0 + (double)a1 * b1 + (double)a2 * b2 + (double)a3 * b3;
            normA += (double)a0 * a0 + (double)a1 * a1 + (double)a2 * a2 + (double)a3 * a3;
            normB += (double)b0 * b0 + (double)b1 * b1 + (double)b2 * b2 + (double)b3 * b3;
        }

        
        for (; i < len; i++) {
            dotProduct += (double)vecA[i] * vecB[i];
            normA += (double)vecA[i] * vecA[i];
            normB += (double)vecB[i] * vecB[i];
        }

        
        if (normA == 0.0 || normB == 0.0) {
            return Double.NaN;
        }

        double similarity = dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
        
        return (similarity + 1.0) / 2.0;
    }

    

    
    private static boolean isND4JAvailable() {
        if (nd4jAvailable == null) {
            synchronized (VectorSimilarityUtil.class) {
                if (nd4jAvailable == null) {
                    nd4jAvailable = checkND4JAvailability();
                }
            }
        }
        return nd4jAvailable;
    }

    
    private static boolean checkND4JAvailability() {
        try {
            Class.forName("org.nd4j.linalg.factory.Nd4j");
            Class.forName("org.nd4j.linalg.ops.transforms.Transforms");
            log.info("[VectorSimilarityUtil] ND4J SIMD optimization enabled (3-5x faster)");
            return true;
        } catch (ClassNotFoundException e) {
            log.info("[VectorSimilarityUtil] ND4J not available, using pure Java fallback");
            return false;
        } catch (Throwable e) {
            log.warn("[VectorSimilarityUtil] ND4J check failed: {}, using pure Java fallback", e.getMessage());
            return false;
        }
    }

    
    public static void resetND4JCheck() {
        synchronized (VectorSimilarityUtil.class) {
            nd4jAvailable = null;
        }
    }
}
