"""Matplotlib-backed chart renderers.

Two concrete renderers in the MVP:

* ``measurement_chart.MeasurementChartRenderer`` — normalised
  horizontal bars per metric per benchmark.
* ``diff_chart.DiffChartRenderer`` — improvements / regressions /
  unchanged per-metric bars vs a stored baseline.

Both depend on matplotlib via ``_mpl``. Callers check
``renderer.is_available()`` before ``render()`` and treat the
``False`` branch as "skip chart, keep going" (``render_or_skip``
encapsulates that idiom).
"""
