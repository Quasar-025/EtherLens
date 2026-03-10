export async function fetchWithBackoff<T>(
    operation: () => Promise<T>,
    maxRetries: number = 3,
    baseDelayMs: number = 1000
): Promise<T> {
    let attempt = 0;
    while (attempt < maxRetries) {
        try {
            return await operation();
        } catch (error: any) {
            attempt++;
            console.warn(`[!] RPC Error on attempt ${attempt}: ${error.message}`);
            
            if (attempt >= maxRetries) {
                throw new Error(`RPC Operation failed after ${maxRetries} attempts.`);
            }
            
            // Exponential backoff: 1s, 2s, 4s...
            const delay = baseDelayMs * Math.pow(2, attempt - 1);
            console.log(`[!] Retrying in ${delay}ms...`);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
    throw new Error("Unreachable");
}