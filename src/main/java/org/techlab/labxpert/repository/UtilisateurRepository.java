package org.techlab.labxpert.repository;

import org.springframework.data.jpa.repository.Query;
import org.techlab.labxpert.entity.Utilisateur;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UtilisateurRepository extends JpaRepository<Utilisateur,Long> {
    @Query("SELECT u FROM Utilisateur u WHERE u.nomUtilisateur = ?1")

    Optional<Utilisateur> findByUsername(String username);
    List<Utilisateur> findByDeletedFalse();
    @Query("SELECT u FROM Utilisateur u WHERE u.nomUtilisateur = ?1 and u.password = ?2")
    Utilisateur findUserByUsernameAndPassword(String username, String password);
}
