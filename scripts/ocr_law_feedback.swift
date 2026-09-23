import Foundation
import PDFKit
import Vision
import AppKit

// Local Apple Vision OCR only. Stdout is consumed directly into encrypted
// workspace storage by the Python driver, never into shared guide text.
guard CommandLine.arguments.count == 2,
      let document = PDFDocument(url: URL(fileURLWithPath: CommandLine.arguments[1])) else {
    exit(2)
}
for index in 0..<document.pageCount {
    guard let page = document.page(at: index) else { continue }
    let bounds = page.bounds(for: .mediaBox)
    let scale = 2.0
    let image = page.thumbnail(of: NSSize(width: bounds.width * scale, height: bounds.height * scale), for: .mediaBox)
    guard let cgImage = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else { exit(3) }
    let request = VNRecognizeTextRequest()
    request.recognitionLevel = .accurate
    request.usesLanguageCorrection = true
    request.recognitionLanguages = ["en-GB"]
    do {
        try VNImageRequestHandler(cgImage: cgImage, options: [:]).perform([request])
        let observations = request.results ?? []
        let text = observations.compactMap { $0.topCandidates(1).first?.string }.joined(separator: "\n")
        let confidence = observations.compactMap { $0.topCandidates(1).first?.confidence }
        let row: [String: Any] = ["page": index + 1, "text": text,
            "annotation_text": page.annotations.compactMap { $0.contents }.joined(separator: "\n"),
            "mean_confidence": confidence.isEmpty ? 0 : confidence.reduce(0,+) / Float(confidence.count)]
        let data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys])
        print(String(data: data, encoding: .utf8)!)
        fflush(stdout)
    } catch { exit(4) }
}
