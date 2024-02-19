from math import prod

import pytest

import libs.ecc_utils as ecc_utils
from libs.ecc_utils import AInvs, Point

from .conftest import CompositeCurve, CurveWithPoints


class TestECCUtils:
    def test_parse_int(self) -> None:
        assert ecc_utils.parse_int("0") == 0
        assert ecc_utils.parse_int("123") == 123
        assert ecc_utils.parse_int("-123") == -123
        assert ecc_utils.parse_int(" \t 123  \t  ") == 123
        assert ecc_utils.parse_int("0xdef") == 0xDEF
        assert ecc_utils.parse_int("-0xdef") == -0xDEF
        assert ecc_utils.parse_int("0b101") == 0b101
        assert ecc_utils.parse_int("-0b101") == -0b101
        assert ecc_utils.parse_int("0o123") == 0o123
        assert ecc_utils.parse_int("-0o123") == -0o123
        with pytest.raises(ValueError):
            ecc_utils.parse_int("")
        with pytest.raises(ValueError):
            ecc_utils.parse_int("12a")
        with pytest.raises(ValueError):
            ecc_utils.parse_int("0x")
        with pytest.raises(ValueError):
            ecc_utils.parse_int("0b")
        with pytest.raises(ValueError):
            ecc_utils.parse_int("0o")
        with pytest.raises(ValueError):
            ecc_utils.parse_int("0xg")
        with pytest.raises(ValueError):
            ecc_utils.parse_int("0b2")
        with pytest.raises(ValueError):
            ecc_utils.parse_int("0o8")

    def test_calc_curve_params_simple2(self, curve_simple2: CurveWithPoints) -> None:
        a_invs, p, G, P = curve_simple2
        a_invs_short = ecc_utils.AInvsShort2((a_invs[3], a_invs[4]))
        assert ecc_utils.calc_curve_params(p, G, P) == a_invs_short

    def test_calc_curve_params_nist(self, curve_nistp256: CurveWithPoints) -> None:
        a_invs, p, G, P = curve_nistp256
        a_invs_short = ecc_utils.AInvsShort2((a_invs[3], a_invs[4]))
        assert ecc_utils.calc_curve_params(p, G, P) == a_invs_short

    def test_b_invariants_simple2(self, curve_simple2: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple2
        b_invs = ecc_utils.BInvs((0, 5, 8, 15))
        assert ecc_utils.b_invariants(a_invs, p) == b_invs

    def test_b_invariants_simple3(self, curve_simple3: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple3
        b_invs = ecc_utils.BInvs((2, 6, 3, 1))
        assert ecc_utils.b_invariants(a_invs, p) == b_invs

    def test_b_invariants_simple5(self, curve_simple5: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple5
        b_invs = ecc_utils.BInvs((9, 11, 12, 1))
        assert ecc_utils.b_invariants(a_invs, p) == b_invs

    def test_b_invariants_nist(self, curve_nistp256: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_nistp256
        b_invs = ecc_utils.BInvs(
            (
                0,
                115792089210356248762697446949407573530086143415290314195533631308867097853945,
                48441365690252319754607072170781500106371620648684588023807393947290771751213,
                115792089210356248762697446949407573530086143415290314195533631308867097853942,
            )
        )
        assert ecc_utils.b_invariants(a_invs, p) == b_invs

    def test_c_invariants_simple2(self, curve_simple2: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple2
        c_invs = ecc_utils.CInvs((16, 6))
        assert ecc_utils.c_invariants(a_invs, p) == c_invs

    def test_c_invariants_simple3(self, curve_simple3: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple3
        c_invs = ecc_utils.CInvs((13, 14))
        assert ecc_utils.c_invariants(a_invs, p) == c_invs

    def test_c_invariants_simple5(self, curve_simple5: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple5
        c_invs = ecc_utils.CInvs((4, 5))
        assert ecc_utils.c_invariants(a_invs, p) == c_invs

    def test_c_invariants_nist(self, curve_nistp256: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_nistp256
        c_invs = ecc_utils.CInvs(
            (144, 73745129047917570410340083507285168261568990675547578651163356492099206447533)
        )
        assert ecc_utils.c_invariants(a_invs, p) == c_invs

    def test_discriminant_simple2(self, curve_simple2: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple2
        disc = 9
        assert ecc_utils.discriminant(a_invs, p) == disc

    def test_discriminant_simple3(self, curve_simple3: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple3
        disc = 15
        assert ecc_utils.discriminant(a_invs, p) == disc

    def test_discriminant_simple5(self, curve_simple5: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple5
        disc = 2
        assert ecc_utils.discriminant(a_invs, p) == disc

    def test_discriminant_nist(self, curve_nistp256: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_nistp256
        disc = 47064476442213300654454205837611899485069387829947879813735601543372794627813
        assert ecc_utils.discriminant(a_invs, p) == disc

    def test_j_invariant_simple(
        self,
        curve_simple2: CurveWithPoints,
        curve_simple3: CurveWithPoints,
        curve_simple5: CurveWithPoints,
    ) -> None:
        a_invs2, p, _, _ = curve_simple2
        a_invs3, _, _, _ = curve_simple3
        a_invs5, _, _, _ = curve_simple5
        j = 15
        assert ecc_utils.j_invariant(a_invs2, p) == j
        assert ecc_utils.j_invariant(a_invs3, p) == j
        assert ecc_utils.j_invariant(a_invs5, p) == j

    def test_j_invariant_nist(self, curve_nistp256: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_nistp256
        j = 7958909377132088453074743217357398615041065282494610304372115906626967530147
        assert ecc_utils.j_invariant(a_invs, p) == j

    def test_long_weier_form(self) -> None:
        a_invs = AInvs((1, 2, 3, 4, 5))
        assert ecc_utils.long_weier_form(a_invs) == a_invs
        a_invs_short2 = ecc_utils.AInvsShort2((6, 7))
        assert ecc_utils.long_weier_form(a_invs_short2) == AInvs((0, 0, 0, 6, 7))
        a_invs_short3 = ecc_utils.AInvsShort3((8, 9, 10))
        assert ecc_utils.long_weier_form(a_invs_short3) == AInvs((0, 8, 0, 9, 10))

    def test_short_weier_form2_simple2(self, curve_simple2: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple2
        a_invs_short = ecc_utils.AInvsShort2((a_invs[3], a_invs[4]))
        assert ecc_utils.short_weier_form2(a_invs, p) == a_invs_short

    def test_short_weier_form2_simple3(self, curve_simple3: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple3
        a_invs_short = ecc_utils.AInvsShort2((6, 9))
        assert ecc_utils.short_weier_form2(a_invs, p) == a_invs_short

    def test_short_weier_form2_simple5(
        self, curve_simple5: CurveWithPoints, curve_simple2: CurveWithPoints
    ) -> None:
        a_invs, p, _, _ = curve_simple5
        a_invs2, _, _, _ = curve_simple2
        a_invs_short = ecc_utils.AInvsShort2((a_invs2[3], a_invs2[4]))
        assert ecc_utils.short_weier_form2(a_invs, p) == a_invs_short

    def test_short_weier_form2_comp(self, curve_composite: CompositeCurve) -> None:
        a_invs, ps, _, _ = curve_composite
        p = prod(ps)
        a_invs_short = ecc_utils.AInvsShort2(
            (
                32798418228515872218120447629717869129404428538293464688068671881164099465865,
                4317186857939532136948539655840672744264293793654688812359700106918997611341,
            )
        )
        assert ecc_utils.short_weier_form2(a_invs, p) == a_invs_short

    def test_short_weier_form3_simple2(self, curve_simple2: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple2
        a_invs_short = ecc_utils.AInvsShort3((0, a_invs[3], a_invs[4]))
        assert ecc_utils.short_weier_form3(a_invs, p) == a_invs_short

    def test_short_weier_form3_simple3(self, curve_simple3: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_simple3
        a_invs_short = ecc_utils.AInvsShort3((a_invs[1], a_invs[3], a_invs[4]))
        assert ecc_utils.short_weier_form3(a_invs, p) == a_invs_short

    def test_short_weier_form3_simple5(
        self, curve_simple5: CurveWithPoints, curve_simple3: CurveWithPoints
    ) -> None:
        a_invs, p, _, _ = curve_simple5
        a_invs3, _, _, _ = curve_simple3
        a_invs_short = ecc_utils.AInvsShort3((a_invs3[1], a_invs3[3], a_invs3[4]))
        assert ecc_utils.short_weier_form3(a_invs, p) == a_invs_short

    def test_isomorphisms_simple52(
        self, curve_simple5: CurveWithPoints, curve_simple2: CurveWithPoints
    ) -> None:
        a_invs5, p, _, _ = curve_simple5
        a_invs2, _, _, _ = curve_simple2

        isos = ecc_utils.isomorphisms(a_invs5, a_invs2, p, just_one=False)
        assert isinstance(isos, list)
        assert set(isos) == {(3, 12, 8, 1), (14, 12, 8, 1)}

    def test_isomorphisms_simple53(
        self, curve_simple5: CurveWithPoints, curve_simple3: CurveWithPoints
    ) -> None:
        a_invs5, p, _, _ = curve_simple5
        a_invs3, _, _, _ = curve_simple3

        isos = ecc_utils.isomorphisms(a_invs5, a_invs3, p, just_one=False)
        assert isinstance(isos, list)
        assert set(isos) == {(8, 0, 8, 7), (9, 0, 8, 7)}

    def test_dual_isomorphism_simple52(
        self, curve_simple5: CurveWithPoints, curve_simple2: CurveWithPoints
    ) -> None:
        a_invs5, p, _, _ = curve_simple5
        a_invs2, _, _, _ = curve_simple2

        isos = ecc_utils.isomorphisms(a_invs5, a_invs2, p, just_one=False)
        isos_dual = ecc_utils.isomorphisms(a_invs2, a_invs5, p, just_one=False)
        assert isinstance(isos, list) and isinstance(isos_dual, list)
        assert len(isos) > 0 and len(isos_dual) > 0
        for iso in isos:
            iso_dual = ecc_utils.dual_isomorphism(iso, p)
            assert iso_dual in isos_dual

    def test_morph_point_simple52(
        self, curve_simple5: CurveWithPoints, curve_simple2: CurveWithPoints
    ) -> None:
        a_invs5, p, G5, P5 = curve_simple5
        a_invs2, _, G2, P2 = curve_simple2
        iso = ecc_utils.isomorphism(a_invs5, a_invs2, p)
        assert iso is not None
        assert ecc_utils.morph_point(iso, p, G5) == G2
        assert ecc_utils.morph_point(iso, p, P5) == P2
        assert ecc_utils.morph_point(iso, p, (G5.x, None)) == (G2.x, None)
        assert ecc_utils.morph_point(iso, p, (P5.x, None)) == (P2.x, None)

    def test_morph_point_simple53(
        self, curve_simple5: CurveWithPoints, curve_simple3: CurveWithPoints
    ) -> None:
        a_invs5, p, G5, P5 = curve_simple5
        a_invs3, _, G3, P3 = curve_simple3
        iso = ecc_utils.isomorphism(a_invs5, a_invs3, p)
        assert iso is not None
        assert ecc_utils.morph_point(iso, p, G5) == G3
        assert ecc_utils.morph_point(iso, p, P5) == P3
        assert ecc_utils.morph_point(iso, p, (G5.x, None)) == (G3.x, None)
        assert ecc_utils.morph_point(iso, p, (P5.x, None)) == (P3.x, None)

    def test_lift_x_simple2(self, curve_simple2: CurveWithPoints) -> None:
        a_invs, p, G, P = curve_simple2
        Gs = ecc_utils.lift_x(a_invs, G.x, [p])
        assert G in Gs
        Ps = ecc_utils.lift_x(a_invs, P.x, [p])
        assert P in Ps

    def test_lift_x_simple3(self, curve_simple3: CurveWithPoints) -> None:
        a_invs, p, G, P = curve_simple3
        Gs = ecc_utils.lift_x(a_invs, G.x, [p])
        assert G in Gs
        Ps = ecc_utils.lift_x(a_invs, P.x, [p])
        assert P in Ps

    def test_lift_x_simple5(self, curve_simple5: CurveWithPoints) -> None:
        a_invs, p, G, P = curve_simple5
        Gs = ecc_utils.lift_x(a_invs, G.x, [p])
        assert G in Gs
        Ps = ecc_utils.lift_x(a_invs, P.x, [p])
        assert P in Ps

    def test_lift_x_nist(self, curve_nistp256: CurveWithPoints) -> None:
        a_invs, p, G, P = curve_nistp256
        Gs = ecc_utils.lift_x(a_invs, G.x, [p])
        assert G in Gs
        Ps = ecc_utils.lift_x(a_invs, P.x, [p])
        assert P in Ps

    def test_lift_x_comp(self, curve_composite: CompositeCurve) -> None:
        a_invs, ps, G, P = curve_composite
        Gs = ecc_utils.lift_x(a_invs, G.x, ps)
        assert G in Gs
        Ps = ecc_utils.lift_x(a_invs, P.x, ps)
        assert P in Ps


class TestPoint:
    def test_init(self) -> None:
        p = Point(1, 2)
        assert p.x == 1
        assert p.y == 2
        assert str(p) == "(1, 2)"
        assert repr(p) == "Point(1, 2)"
        p = Point((1, 2))
        assert p.x == 1
        assert p.y == 2
        p = Point("1, 2")
        assert p.x == 1
        assert p.y == 2
        p = Point(" \t (1, 2)\t \t")
        assert p.x == 1
        assert p.y == 2
        p = Point("{1, 2}")
        assert p.x == 1
        assert p.y == 2
        p = Point("[1, 2]")
        assert p.x == 1
        assert p.y == 2
        with pytest.raises(ValueError):
            p = Point(1)
        with pytest.raises(TypeError):
            p = Point(1, 2, 3)  # type: ignore
        with pytest.raises(ValueError):
            p = Point("1")
        with pytest.raises(ValueError):
            p = Point("(1, 2, 3)")

    def test_on_curve(self, curve_nistp256: CurveWithPoints) -> None:
        a_invs, p, G, P = curve_nistp256
        assert G.on_curve(a_invs, p)
        assert P.on_curve(a_invs, p)
        Q = Point(
            87654599616384782261468144539084575745741642173476572116818534813937734962097,
            36148941393881143608132668786672910560318200997860338691667991924250926912278,
        )
        assert not Q.on_curve(a_invs, p)
