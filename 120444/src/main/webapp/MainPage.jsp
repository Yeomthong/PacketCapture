<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ page import="com.packet.main.*, java.util.ArrayList, org.jnetpcap.*"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html lang="en">
<head>
<script
	src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/js/all.min.js"
	crossorigin="anonymous"></script>
<script
	src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>

<link
	href="https://cdn.jsdelivr.net/npm/simple-datatables@latest/dist/style.css"
	rel="stylesheet" />
<link href="css/styles.css" rel="stylesheet" />

<meta charset="utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<meta name="viewport"
	content="width=device-width, initial-scale=1, shrink-to-fit=no" />
<meta name="description" content="" />
<meta name="author" content="" />

<title>패킷 캡쳐 프로그램</title>
</head>

<body class="sb-nav-fixed sb-sidenav-toggled">
	<%
	int num = Integer.parseInt(request.getParameter("num"));
	int x = Integer.parseInt(request.getParameter("x"));

	// 장치 이름 출력 : device.getName()
	//PcapIf device = p.getAlldevs().get(num);

	PacketSniffer p = (PacketSniffer) session.getAttribute("p");
	p.setModel(num, x);

	ArrayList<JPacketHandlerModel> model = p.getModel();
	%>
	<nav
		class="sb-topnav navbar navbar-expand navbar-dark bg-dark HeaderMarignCenter">
		<!-- Navbar Brand-->
		<a class="navbar-brand ps-3 text-center" href="FirstPage.jsp"> 2조
		</a>
	</nav>
	<div id="layoutSidenav">
		<div id="layoutSidenav_content">

			<main>
				<div class="container-fluid px-4">
					<h1 class="mt-4">패킷 캡쳐</h1>
					<ol class="breadcrumb mb-4">
						<li class="breadcrumb-item active">캡쳐 중</li>
					</ol>
					<div class="row">
						<div>
							<div class="card2 bg-primary text-white text-center mb-4 btnAli">
								<button class="btn text-white">Protocol</button>
							</div>
						</div>
					</div>
					<div class="btnList">
						<input type="file" id="file" style="display: none">
						<button class="btn-primary" onclick="fileRead()">파일열기</button>
						<button class="btn-primary">
							<a class="textWhite" href="" id="download">파일저장</a>
						</button>
						<button class="btn-primary" onclick="start()">패킷시작</button>
					</div>
					<br> <br>

					<div class="card mb-4">
						<div class="card-header">
							<i class="fas fa-table me-1"></i> 패킷 목록
						</div>
						<div class="card-body" id="tableDiv">
							<table class="scrolltable" id="datatablesSimple">
								<thead>
									<tr>
										<th>NO</th>
										<th>Time</th>
										<th>Source</th>
										<th>Destination</th>
										<th>Protocol</th>
										<th>Length</th>
										<th>Information</th>
										<th style="display: none;">info</th>
										<th style="display: none;">payloadHeader</th>
										<th style="display: none;">payloadHex</th>
									</tr>
								</thead>

								<tbody id="aaa">
									<%
									for (JPacketHandlerModel a : model) {
										int number = a.getNum();

										String info = a.getFrame().toString() + a.getEthernet().toString() + a.getInternetProtocol().toString()
										+ a.getTransportLayer().toString() + a.getApplicationLayer().toString();
										info = info.replaceAll("<", "&lt;").replaceAll(">", "&gt;");
										String payloadHeader = a.getPacket().toString().replaceAll("<", "&lt;").replaceAll(">", "&gt;");
										String payloadHex = a.getPayloadHex();
									%>
									<tr id="<%=number%>" onclick='javascript:trClick(this);'>
										<td id="num<%=number%>"><%=a.getNum()%></td>
										<td id="time<%=number%>"><%=a.getTime().toString()%></td>
										<td id="source<%=number%>"><%=a.getSourceIp().toString()%></td>
										<td id="destination<%=number%>"><%=a.getDestinationIp().toString()%></td>
										<td id="protocol<%=number%>"><%=a.getProtocol().toString()%></td>
										<td id="length<%=number%>"><%=a.getLength().toString()%></td>
										<td id="information<%=number%>"><%=a.getInfomation().toString()%></td>

										<td style="display: none;" id="info<%=number%>"><%=info%></td>
										<td style="display: none;" id="payloadHeader<%=number%>"><%=payloadHeader%></td>
										<td style="display: none;" id="payloadHex<%=number%>"><%=payloadHex%></td>
									</tr>
									<%
									}
									%>

								</tbody>
							</table>
						</div>
					</div>

					<div class="card mb-4">
						<div class="card-header">
							<i class="fas fa-table me-1"></i> 패킷 세부정보
						</div>
						<div class="card-body">
							<table class="scrolltable" id="info">
								<tbody>
								</tbody>
							</table>
						</div>
					</div>


					<div class="card mb-4">
						<div class="card-header">
							<i class="fas fa-table me-1"></i>Payload [HEADER]
						</div>
						<div class="card-body">
							<table class="scrolltable" id="payloadHeader">
								<thead></thead>
								<tbody></tbody>
							</table>
						</div>
					</div>

					<div class="card mb-4">
						<div class="card-header">
							<i class="fas fa-table me-1"></i>Payload [HEX]
						</div>
						<div class="card-body">
							<table class="scrolltable" id="payloadHex">
								<thead></thead>
								<tbody></tbody>
							</table>
						</div>
					</div>
				</div>
			</main>

			<footer class="py-4 bg-light mt-auto">
				<div class="container-fluid px-4">
					<div
						class="d-flex align-items-center justify-content-between small">
						<div class="text-muted">Copyright &copy; Your Website 2021</div>
						<div>
							<a href="#">Privacy Policy</a> &middot; <a href="#">Terms&amp;
								Conditions</a>
						</div>
					</div>
				</div>
			</footer>

		</div>
	</div>

	<script type="text/javascript">
		function trClick(tr) {
			var table = document.getElementById("datatablesSimple");

			var trIdx = tr.rowIndex;
			// alert('클릭한 TR index : ' + (trIdx - 1));

			tr = $("tr:eq(" + trIdx + ")");

			var td = tr.children();

			var id = td.eq(0).text();
			// alert(id);

			var info = td.eq(7).text();
			// alert(info);
			info = info.replace(/\n/gi, "<br/>");
			info = info.replace(/\t/gi, "&emsp;&emsp;&emsp;&emsp;");
			$('#info').empty();
			$("#info").append(info);

			var payloadHeader = td.eq(8).text();
			/^.{0,4}$/
			payloadHeader = payloadHeader.replace(/\n/gi, "<br/>");
			payloadHeader = payloadHeader.replace(/\t/gi, "&emsp;&emsp;&emsp;&emsp;");
			payloadHeader = payloadHeader.replace(/ /gi, "&nbsp;");
			$('#payloadHeader').empty();
			$("#payloadHeader").append(payloadHeader);

			var payloadHex = td.eq(9).text();
			payloadHex = payloadHex.replace(/\n/gi, "<br/>");
			payloadHex = payloadHex.replace(/\t/gi, "&emsp;&emsp;&emsp;&emsp;");
			payloadHex = payloadHex.replace(/ /gi, "&nbsp;");
			$('#payloadHex').empty();
			$("#payloadHex").append(payloadHex);

		}

		//다운로드 하이퍼링크에 클릭 이벤트 발생시 saveCSV 함수를 호출하도록 이벤트 리스너를 추가

		document.addEventListener('DOMContentLoaded', function() {
			document.getElementById('download').addEventListener('click',
					function() {
						console.log("함수실행");
						var DateName = new Date();
						var fileName = String(DateName);
						saveCSV(fileName); // CSV파일 다운로드 함수 호출
						return false;
					})
		});

		//CSV 생성 함수
		function saveCSV(fileName) {
			//CSV 문자열 생성
			let downLink = document.getElementById('download');
			let csv = ''; //CSV최종 문자열을 저장하는 변수
			let rows = document.querySelectorAll("#aaa tr"); // 테이블에서 행 요소들을 모두 선택

			//행단위 루핑
			for (var i = 0; i < rows.length; i++) {
				let cells = rows[i].querySelectorAll("td, th");
				let row = [];
				//행의 셀 값을 배열로 얻기
				decodeURI(cells);
				cells.forEach(function(cell) {
					row.push(cell.innerHTML);
				});

				csv += row.join(',') + (i != rows.length - 1 ? '\n' : ''); // 배열을 문자열+줄바꿈으로 변환
			}

			//CSV 파일 저장
			csvFile = new Blob([ csv ], {
				type : "text/csv"
			}); // 생성한 CSV 문자열을 Blob 데이터로 생성
			downLink.href = window.URL.createObjectURL(csvFile); // Blob 데이터를 URL 객체로 감싸 다운로드 하이퍼링크에 붙임.
			downLink.download = fileName; // 인자로 받은 다운로드 파일명을 지정
		}
	</script>

	<script
		src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"
		crossorigin="anonymous"></script>
	<script src="js/scripts.js"></script>
	<script
		src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.8.0/Chart.min.js"
		crossorigin="anonymous"></script>
	<script src="https://cdn.jsdelivr.net/npm/simple-datatables@latest"
		crossorigin="anonymous"></script>
	<script src="js/datatables-simple-demo.js"></script>
</body>
</html>
