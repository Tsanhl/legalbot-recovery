ObjC.import('Foundation');
ObjC.import('AppKit');
ObjC.import('Quartz');
ObjC.import('PDFKit');
ObjC.import('Vision');
function run(argv) {
  const doc = $.PDFDocument.alloc.initWithURL($.NSURL.fileURLWithPath(argv[0]));
  const rows=[];
  const count=argv[1] ? Math.min(Number(argv[1]),Number(doc.pageCount)) : Number(doc.pageCount);
  for(let i=0;i<count;i++) {
    const page=doc.pageAtIndex(i);
    const thumbnail=page.thumbnailOfSizeForBox($.NSMakeSize(1600,2200),0);
    const ci=$.CIImage.imageWithData(thumbnail.TIFFRepresentation);
    const request=$.VNRecognizeTextRequest.alloc.init;
    request.recognitionLevel=0;
    request.usesLanguageCorrection=true;
    request.recognitionLanguages=$.NSArray.arrayWithObject($('en-GB'));
    const handler=$.VNImageRequestHandler.alloc.initWithCIImageOptions(ci,$.NSDictionary.dictionary);
    const err=Ref();
    if(!handler.performRequestsError($.NSArray.arrayWithObject(request),err)) throw new Error('local_vision_ocr_failed');
    const lines=[];let confidence=0;
    const observations=request.results;
    for(let j=0;j<Number(observations.count);j++) {
      const candidate=observations.objectAtIndex(j).topCandidates(1).objectAtIndex(0);
      lines.push(ObjC.unwrap(candidate.string));confidence+=Number(candidate.confidence);
    }
    const annotations=[];
    for(let j=0;j<Number(page.annotations.count);j++) {
      const text=ObjC.unwrap(page.annotations.objectAtIndex(j).contents);
      if(text) annotations.push(text);
    }
    rows.push({page:i+1,text:lines.join('\n'),annotation_text:annotations.join('\n'),mean_confidence:observations.count ? confidence/Number(observations.count) : 0});
  }
  return JSON.stringify(rows);
}
