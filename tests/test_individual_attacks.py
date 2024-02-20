from typing import cast

import pytest

from libs.attacks.ecc_mov import MAX_DEGREE, embedding_degree, mov_attack
from libs.attacks.ecc_pohlig_hellman import pohlig_hellman_attack
from libs.attacks.ecc_singular import singular_attack
from libs.attacks.ecc_smart import smart_attack
from libs.ecc_utils import AInvs
from libs.sage_types import ECFF, GF, ECFFPoint, EllipticCurve, FFPmodn

from .conftest import CurveWithPoints


def make_curve(a_invs: AInvs, p: int) -> ECFF:
    F = cast(FFPmodn, GF(p))
    return cast(ECFF, EllipticCurve(F, a_invs))


def make_curve_points(params: CurveWithPoints) -> tuple[ECFF, ECFFPoint, ECFFPoint]:
    a_invs, p, G, P = params
    E = make_curve(a_invs, p)
    return E, E(G), E(P)


class TestMOV:
    def test_embedding_degree_supersingular(self, curve_supersingular: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_supersingular
        E = make_curve(a_invs, p)
        assert embedding_degree(E, MAX_DEGREE) == 2

    def test_embedding_degree_nist(self, curve_nistp256: CurveWithPoints) -> None:
        a_invs, p, _, _ = curve_nistp256
        E = make_curve(a_invs, p)
        assert embedding_degree(E, MAX_DEGREE) == -1

    def test_mov_supersingular(self, curve_supersingular: CurveWithPoints) -> None:
        _, G, P = make_curve_points(curve_supersingular)
        res = mov_attack(G, P)
        for n in res.n:
            assert n * G == P

    def test_mov_anomalous1(self, curve_anomalous1: CurveWithPoints) -> None:
        _, G, P = make_curve_points(curve_anomalous1)
        with pytest.raises(ValueError):
            mov_attack(G, P)


class TestPohligHellman:
    def test_pohlig_hellman_smooth1(self, curve_smooth1: CurveWithPoints) -> None:
        _, G, P = make_curve_points(curve_smooth1)
        res = pohlig_hellman_attack(G, P)
        for n in res.n:
            assert n * G == P

    def test_pohlig_hellman_smooth2(self, curve_smooth2: CurveWithPoints) -> None:
        _, G, P = make_curve_points(curve_smooth2)
        res = pohlig_hellman_attack(G, P, allow_partial=True)
        assert 9092500866606561 in res.n

    def test_pohlig_hellman_nist(self, curve_nistp256: CurveWithPoints) -> None:
        _, G, P = make_curve_points(curve_nistp256)
        with pytest.raises(ValueError):
            pohlig_hellman_attack(G, P)


class TestSingular:
    def test_singular_node(self, curve_singular_node: CurveWithPoints) -> None:
        a_invs, p, G, P = curve_singular_node
        F = cast(FFPmodn, GF(p))
        res = singular_attack(a_invs, F, G.x, G.y, P.x, P.y, use_generic_log=True)
        assert 571653 in res.n

    def test_singular_cusp(self, curve_singular_cusp: CurveWithPoints) -> None:
        a_invs, p, G, P = curve_singular_cusp
        F = cast(FFPmodn, GF(p))
        res = singular_attack(a_invs, F, G.x, G.y, P.x, P.y)
        assert 550923845938458749857348948503485975983479875983475983745871 in res.n


class TestSmart:
    def test_smart_anomalous1(self, curve_anomalous1: CurveWithPoints) -> None:
        _, G, P = make_curve_points(curve_anomalous1)
        res = smart_attack(G, P)
        for n in res.n:
            assert n * G == P

    def test_smart_anomalous2(self, curve_anomalous2: CurveWithPoints) -> None:
        _, G, P = make_curve_points(curve_anomalous2)
        res = smart_attack(G, P)
        for n in res.n:
            assert n * G == P

    def test_smart_supersingular(self, curve_supersingular: CurveWithPoints) -> None:
        _, G, P = make_curve_points(curve_supersingular)
        with pytest.raises(ValueError):
            smart_attack(G, P)

    def test_smart_smooth1(self, curve_smooth1: CurveWithPoints) -> None:
        _, G, P = make_curve_points(curve_smooth1)
        with pytest.raises(ValueError):
            smart_attack(G, P)
