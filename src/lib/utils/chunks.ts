export const splitFilesIntoChunks = async (fileData: ArrayBuffer) => {
    const chunkSize = 8 * 1024 * 1024 // 8MB
    const chunks = []
    for (let i = 0; i < fileData.byteLength; i += chunkSize) {
        const chunk = fileData.slice(i, i + chunkSize)
        chunks.push(chunk)
    }
    return chunks
}