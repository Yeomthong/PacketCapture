<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ page import="com.packet.main.*, java.util.*, org.jnetpcap.PcapIf"%>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<meta name="viewport"
	content="width=device-width, initial-scale=1, shrink-to-fit=no" />
<meta name="description" content="" />
<meta name="author" content="" />
<title>패킷 캡쳐 프로그램</title>
<link
	href="https://cdn.jsdelivr.net/npm/simple-datatables@latest/dist/style.css"
	rel="stylesheet" />
<link href="css/styles.css" rel="stylesheet" />
<script
	src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/js/all.min.js"
	crossorigin="anonymous"></script>
</head>
<body class="sb-nav-fixed sb-sidenav-toggled">

	<%
	PacketSniffer p = new PacketSniffer();
	List<PcapIf> alldevs = p.printAllDevs();
	System.out.println(p);
	session.setAttribute("p", p);
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
						<li class="breadcrumb-item active">열심히 했으니까 넓은 마음으로 봐주자</li>
					</ol>
				</div>

				<div class="start-body">
					<table id="datatablesSimple">
						<thead>
							<tr>
								<th>NO</th>
								<th>Dev_Name</th>
							</tr>
						</thead>
						<tfoot>
							<tr>
								<th>NO</th>
								<th>Dev_Name</th>
							</tr>
						</tfoot>
						<tbody>
							<%
							int num = 0;
							for (PcapIf device : alldevs) {
							%>
							<tr onclick="javascript:fSend(this);">
								<td><%=num++%></td>
								<td><a href="#"><%=device.getDescription()%></a></td>
							</tr>
							<%
							}
							%>
						</tbody>
					</table>
				</div>
			</main>

			<footer class="py-4 bg-light mt-auto">
				<div class="container-fluid px-4">
					<div
						class="d-flex align-items-center justify-content-between small">
						<div class="text-muted">Copyright &copy; Your Website 2021</div>
						<div>
							<a href="#">Privacy Policy</a> &middot; <a href="#">Terms
								&amp; Conditions</a>
						</div>
					</div>
				</div>
			</footer>

		</div>
	</div>
	<script type="text/javascript">
		function fSend(tr) {
			var x = prompt("패킷캡쳐 횟수");
			var num = tr.rowIndex - 1;
			console.log(num);

			/*  if(x == (/[^0-9]/g)) {
			      alert("숫자가 아닙니다.");
			      return false;
			   } */

			if (x.length > 0) {
				location.href = "MainPage.jsp?num=" + num + "&x=" + x;
			} else
				return false;
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
