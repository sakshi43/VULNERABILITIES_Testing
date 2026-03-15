from fastapi import FastAPI,Request,Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse,FileResponse
from secure import scan_api
from report import generate_pdf
import uvicorn
import traceback
app=FastAPI()
scan_results=None
templates = Jinja2Templates(directory="templates")
@app.get('/')
async def index(request:Request):
    
    return templates.TemplateResponse("index.html", {"request": request, "scan_results": None})
@app.post('/scanning')
async def scanning(request:Request,endpoint: str = Form(...)):
    try:
        global scan_results
        scan_results=scan_api(endpoint)

        return templates.TemplateResponse('index.html',{'request':request,'scan_results':scan_results})
    except Exception as e:
        return templates.TemplateResponse('index.html',{'msg':str(e)})

@app.get("/download")
async def download():
    if scan_results is None:
        return JSONResponse({'msg': 'No scan has been run yet'}, status_code=400)
    try:
        generate_pdf(scan_results)
        print(traceback.format_exc())
        return FileResponse("report.pdf", filename="report.pdf")
    except Exception as e:
        return JSONResponse({'msg': str(e)}, status_code=500)


if __name__=="__main__":
    uvicorn.run(app, port=5012)