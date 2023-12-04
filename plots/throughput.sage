class PlottingData:
    def __init__(self, pts, label, color, marker, pointsize):
        self.pts = pts
        self.label = label
        self.color = color
        self.marker = marker
        self.pointsize = pointsize

grandline_points = [(4, 11.47), (8, 8.52), (16, 7.50320268239), (32, 4.0055546173), (64, 2.04129615247)]
brandpiper_points = [(4, 0.39499733246), (8, 0.20183841153), (16, 0.11341804678), (32, 0.03182482496), (64, 0.01130489727)]
drand_points = [(4, 2.86929982552), (8, 2.70285106613), (16, 2.207765447), (32, 1.27143965112)]
optrand_points = [(4, 1.96755033196), (8, 1.93728530139), (16, 1.8665096858), (32, 1.60442498593), (64, 0.97888915042)]
        
grandline_data = PlottingData(grandline_points, "GRandLine", "blue", None, 40)
brandpiper_data = PlottingData(brandpiper_points, "BRandPiper", "red", "D", 40)
drand_data = PlottingData(drand_points, "Drand", "green", "s", 40)
optrand_data = PlottingData(optrand_points, "Optrand", "purple", (5, 1, 0), 80)

data = [grandline_data, brandpiper_data, drand_data, optrand_data]
final_plot = plot([])

for protocol_data in data:
    final_plot += line(protocol_data.pts, scale='linear', base=2, legend_label=protocol_data.label, color=protocol_data.color)
    for point in protocol_data.pts:
        final_plot += point2d(point, pointsize=protocol_data.pointsize, marker=protocol_data.marker, color=protocol_data.color)
    
final_plot.axes_labels(['Number of nodes', 'Beacons per sec. (Average of 3 runs)'])
final_plot.show(frame=True, gridlines=[[2**i for i in range(2, 7)], range(1, 12)])
